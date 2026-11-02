// ============================================================
// 邮件研判 (Email Triage) — 钓鱼/垃圾四态判定 + 恶意信号 + 验证剧本
// 文本入口: POST /secops/email/triage   SSE: start→parsing→analyzing→report→complete
// 截图入口: POST /secops/email/triage/image 前置 transcribing→transcript 后接同一管线
//
// 注意: 邮件接口事件名走 SSE event: 行 (区别于 secops 其他接口的
// event:message + type 平铺进 data), 因此自带解析器而非复用 consumeSSE。
// ============================================================

// ---- 展示映射 (与后端 email_triage.py 契约对齐) ----
const EMAIL_CLS_LABEL = {
    phishing:   { text: "恶意攻击", en: "Phishing",   cls: "v-phishing" },
    spam:       { text: "垃圾骚扰", en: "Spam",       cls: "v-spam" },
    suspicious: { text: "可疑",     en: "Suspicious", cls: "v-suspicious" },
    benign:     { text: "正常",     en: "Benign",     cls: "v-benign" },
};
const EMAIL_PHISH_TYPE = {
    credential_phishing: "凭据钓鱼", malware_delivery: "恶意附件投毒",
    bec_fraud: "商务冒充诈骗 (BEC)", extortion_scam: "勒索恐吓",
    lottery_scam: "中奖诈骗", none: "—",
};
const EMAIL_SIGNAL_CAT = {
    sender_spoof: "发件人伪造", domain_lookalike: "域名仿冒", link_mismatch: "链接欺骗",
    urgency_tactic: "紧迫话术", credential_request: "索取凭据", dangerous_attachment: "危险附件",
    brand_impersonation: "品牌仿冒", grammar_anomaly: "语言异常", bulk_marker: "群发特征",
    normal_signal: "正常信号", other: "其他",
    // LLM 常见自造类别 (后端 indicator.category 未做白名单归一) — 前端兜底映射
    domain_typosquatting: "域名仿冒", urgency_threat: "紧迫话术",
    credential_harvesting: "索取凭据", malicious_attachment: "危险附件",
};

let emailAbort = null;      // 当前研判的 AbortController (停止按钮用)
let emailAutoVerify = false; // 本轮沙箱验证是否启用 (parsing 事件告知, analyzing 时收尾 verify 阶段)

// ---- 流水/事件流小工具 (与 app.js secopsStage/secopsFinding 同模式, 限定邮件容器) ----
function emailStage(name, state) {
    const el = document.querySelector(`#email-pipeline .secops-stage[data-stage="${name}"]`);
    if (!el) return;
    el.classList.remove("st-active", "st-done", "st-skip");
    if (state) el.classList.add(`st-${state}`);
}

function emailFinding(html) {
    const el = document.getElementById("email-findings");
    if (!el) return;
    const div = document.createElement("div");
    div.className = "finding-row";
    div.innerHTML = html;
    el.appendChild(div);
    el.scrollTop = el.scrollHeight;
}

function emailStatus(text) {
    document.getElementById("email-status").textContent = text;
}

// 新一轮研判前清场: 事件流/判定面板/报告区复位, 流水阶段回归初始
function emailReset() {
    document.getElementById("email-findings").innerHTML = "";
    document.getElementById("secops-email-report").classList.add("hidden");
    document.getElementById("secops-email-report").innerHTML = "";
    const verdictEl = document.getElementById("email-verdict");
    verdictEl.textContent = "—";
    verdictEl.className = "email-verdict";
    document.getElementById("email-confidence").textContent = "等待研判";
    document.getElementById("email-phish-type").textContent = "—";
    document.getElementById("email-intent").textContent = "—";
    document.getElementById("email-signal-count").textContent = "—";
    emailStatus("未开始");
}

// ---- SSE 解析 (事件名在 event: 行, data: 行是 JSON) ----
async function consumeEmailSSE(response, onEvent) {
    if (!response.ok) {
        const text = await response.text().catch(() => "");
        throw new Error(`HTTP ${response.status}: ${text.slice(0, 200)}`);
    }
    if (!response.body) throw new Error("浏览器不支持 ReadableStream");

    const reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let buf = "";
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        // SSE 块以空行分隔
        let sep;
        while ((sep = buf.search(/\r?\n\r?\n/)) >= 0) {
            const block = buf.slice(0, sep);
            buf = buf.slice(sep).replace(/^\r?\n\r?\n/, "");
            let etype = "message";
            let dataLine = "";
            for (const line of block.split(/\r?\n/)) {
                if (line.startsWith("event:")) etype = line.slice(6).trim();
                else if (line.startsWith("data:")) dataLine += line.slice(5).trim();
            }
            if (!dataLine) continue;
            try {
                onEvent(etype, JSON.parse(dataLine));
            } catch (e) {
                console.warn("[EmailSSE] JSON parse error:", dataLine, e);
            }
        }
    }
}

// ---- SSE 事件渲染 ----
function handleEmailEvent(etype, d) {
    console.log("[Email SSE]", etype, d);

    if (etype === "start") {
        // 截图入口内层管线会再发一次 start — 只推进阶段, 不清场
        emailStage("parse", "active");
        emailStatus("解析中…");

    } else if (etype === "transcribing") {
        emailStage("transcribe", "active");
        emailStatus("视觉转写中…");

    } else if (etype === "transcript") {
        emailStage("transcribe", "done");
        emailFinding(`<span class="f-tag tag-scout">转写</span> 完成 (${d.message || ""}) <details class="email-transcript"><summary>查看转写文本</summary><pre>${escapeHtml(d.transcript || "")}</pre></details>`);

    } else if (etype === "parsing") {
        // 确定性解析完成: 信号先到先显 (毫秒级代码层验证, 不等 LLM)
        emailStage("parse", "done");
        emailAutoVerify = !!d.auto_verify;
        // 沙箱启用时亮 verify (证据将进研判); 未启用灰置, 直接进语义研判
        if (emailAutoVerify) {
            emailStage("verify", "active");
            emailStatus("沙箱验证中…");
        } else {
            emailStage("verify", "skip");
            emailStage("analyze", "active");
            emailStatus("语义研判中…");
        }
        emailFinding(`<span class="f-tag tag-triage">解析</span> ${escapeHtml(d.message || "")}`);
        const signals = d.signals || [];
        signals.forEach((s) => {
            const cat = EMAIL_SIGNAL_CAT[s.category] || s.category || "?";
            emailFinding(`<span class="f-tag tag-analyst">信号</span> <b>[${escapeHtml(cat)}]</b> ${escapeHtml(s.description || "")}`);
        });
        if (!signals.length) emailFinding(`<span class="f-tag tag-critic">信号</span> 代码层未命中确定性恶意模式`);

    } else if (etype === "verifying") {
        emailStage("verify", "active");
        emailStatus("沙箱验证中…");
        emailFinding(`<span class="f-tag tag-scout">沙箱</span> ${escapeHtml(d.message || "urlscan 代访验证中…")}`);

    } else if (etype === "analyzing") {
        // 沙箱窗口结束 (无论有无证据) — verify 收尾, 进入语义研判
        if (emailAutoVerify) emailStage("verify", "done");
        emailStage("analyze", "active");
        emailStatus("语义研判中…");

    } else if (etype === "report") {
        emailStage("analyze", "done");
        emailStage("report", "done");
        emailStatus("完成 ✓");
        renderEmailVerdict(d.result || {});
        renderEmailReport(d.result || {});
        // 沙箱结论随报告交付 (验证卡数据源; 信号卡已并入 indicators 渲染)
        if ((d.result || {}).sandbox_link_verdicts) {
            renderLinkVerdicts(d.result.sandbox_link_verdicts);
        }
        emailFinding(`<span class="f-tag tag-critic">报告</span> ${escapeHtml(d.message || "研判完成")}`);

    } else if (etype === "link_report") {
        // v2: link_report 只在部分链接等待窗超时被取消时到达 (未参与研判的后补告知)
        emailFinding(`<span class="f-tag tag-scout">沙箱</span> ${escapeHtml(d.message || "部分链接验证超时")}`);
        renderLinkVerdicts(d.link_verdicts || [], "append");

    } else if (etype === "complete") {
        emailStatus("完成 ✓");

    } else if (etype === "error") {
        emailStatus("失败 ✗");
        emailFinding(`<span class="f-tag tag-error">错误</span> ${escapeHtml(d.message || "邮件分析失败")}`);
    }
}

// ---- 判定结果面板 (右侧) ----
function renderEmailVerdict(r) {
    const cls = EMAIL_CLS_LABEL[r.classification] || EMAIL_CLS_LABEL.suspicious;
    const verdictEl = document.getElementById("email-verdict");
    verdictEl.textContent = cls.text;
    verdictEl.className = `email-verdict ${cls.cls}`;
    document.getElementById("email-confidence").textContent =
        typeof r.confidence === "number" ? `置信度 ${(r.confidence * 100).toFixed(0)}%` : "置信度 —";
    document.getElementById("email-phish-type").textContent =
        EMAIL_PHISH_TYPE[r.phishing_type] || r.phishing_type || "—";
    document.getElementById("email-intent").textContent = r.intent_summary || "—";
    const detN = (r.deterministic_signals || []).length;
    const semN = (r.indicators || []).length - detN;
    document.getElementById("email-signal-count").textContent =
        `代码验证 ${detN} · 语义分析 ${Math.max(semN, 0)}`;
    if (r.status === "degraded") {
        document.getElementById("email-confidence").textContent += " · 降级模式 (LLM 不可用)";
    }
}

// ---- 报告区渲染 ----
// 信号卡: kind=code → [代码验证] 徽章; kind=sem → [语义分析]
function emailSignalCard(sig, kind) {
    const cat = EMAIL_SIGNAL_CAT[sig.category] || sig.category || "other";
    const isNormal = sig.category === "normal_signal";
    const tagCls = kind === "code" ? "tag-critic" : isNormal ? "tag-critic" : "tag-analyst";
    const kindText = kind === "code" ? "代码验证" : "语义分析";
    return `<div class="signal-card${isNormal ? " signal-normal" : ""}">
        <div class="signal-head"><span class="f-tag ${tagCls}">${kindText}</span><span class="signal-cat">${escapeHtml(cat)}</span></div>
        <div class="signal-desc">${escapeHtml(sig.description || "")}</div>
        <div class="signal-evidence mono">${escapeHtml(sig.evidence || "")}</div>
    </div>`;
}

function renderEmailReport(r) {
    const el = document.getElementById("secops-email-report");
    el.classList.remove("hidden");

    // 确定性信号 evidence 集合 — indicators 里命中的标 [代码验证] (LLM 采纳的代码信号)
    const detEv = new Set((r.deterministic_signals || []).map((s) => (s.evidence || "").toLowerCase()));
    const detCards = (r.deterministic_signals || []).map((s) => emailSignalCard(s, "code")).join("");
    const semSignals = (r.indicators || []).filter((i) => !detEv.has((i.evidence || "").toLowerCase()));
    const semCards = semSignals.map((s) => emailSignalCard(s, "sem")).join("");

    // 解析产物: headers 键值表 + URL/附件清单 (URL 纯文本展示 — 防误点, 与 OPSEC 一致)
    const parsed = r.parsed || {};
    const hdrRows = Object.entries(parsed.headers || {})
        .map(([k, v]) => `<tr><td class="mono">${escapeHtml(k)}</td><td class="mono">${escapeHtml(String(v))}</td></tr>`).join("");
    const urls = (parsed.urls || []).map((u) => `<div class="email-url mono">${escapeHtml(u)}</div>`).join("");
    const atts = (parsed.attachments || []).map((a) => `<span class="email-att">${escapeHtml(a)}</span>`).join(" ");

    // 验证剧本: 情报站外链 (新窗口隔离) + 可复制命令
    const pb = r.verification_playbook || {};
    const stepCard = (s) => {
        const actions = (s.actions || [])
            .filter((a) => /^https:\/\//.test(a.url || ""))   // 只放行 https 情报站链接, 防协议注入
            .map((a) => `<a href="${escapeHtml(a.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(a.label || a.url)}</a>`)
            .join("");
        return `<div class="pb-step">
            <div class="pb-step-name">${escapeHtml(s.step || "")}</div>
            <div class="pb-how">${escapeHtml(s.how || "")}</div>
            ${actions ? `<div class="pb-actions">${actions}</div>` : ""}
            ${s.command ? `<div class="pb-cmd-wrap"><pre class="mono">${escapeHtml(s.command)}</pre><button class="btn-ghost pb-copy" data-cmd="${escapeHtml(s.command)}">复制</button></div>` : ""}
        </div>`;
    };
    const linkSteps = (pb.link_verification || []).map(stepCard).join("");
    const attSteps = (pb.attachment_verification || []).map(stepCard).join("");

    el.innerHTML = `
        <div class="panel email-report-panel">
            <div class="panel-head">📧 邮件研判报告 <span class="t-dim">判定理由 · 信号明细 · 解析产物 · 验证剧本</span></div>
            <div class="email-report-body">
                <div class="email-reason"><h4>判定理由</h4><p>${escapeHtml(r.verdict_reason || "—")}</p></div>
                <div class="email-reason"><h4>发件人身份分析</h4><p>${escapeHtml(r.spoofing_analysis || "—")}</p></div>

                <h4 class="email-sec-title">代码层确定性信号 <span class="t-dim">正则验证过的事实, 零幻觉</span></h4>
                ${detCards || `<p class="t-dim">未命中任何确定性恶意模式 (header/URL/附件均正常)</p>`}

                <h4 class="email-sec-title">语义研判依据 <span class="t-dim">LLM 话术/意图/仿冒分析, 均带原文证据</span></h4>
                ${semCards || `<p class="t-dim">无补充语义依据</p>`}

                <h4 class="email-sec-title">解析产物</h4>
                ${hdrRows ? `<table class="email-hdrs"><tbody>${hdrRows}</tbody></table>` : `<p class="t-dim">未提取到 headers</p>`}
                ${urls ? `<div class="email-sub-label">链接 (${(parsed.urls || []).length}) — 纯文本展示, 请勿直接点击</div>${urls}` : ""}
                ${atts ? `<div class="email-sub-label">附件名 (${(parsed.attachments || []).length})</div><div>${atts}</div>` : ""}
                ${parsed.received_count ? `<div class="email-sub-label">Received 跳数: ${parsed.received_count}</div>` : ""}

                <div id="email-link-verdicts"></div>

                ${(linkSteps || attSteps) ? `
                <h4 class="email-sec-title">安全验证剧本 <span class="t-dim">${escapeHtml(pb.principle || "")}</span></h4>
                ${linkSteps ? `<div class="email-sub-label">链接验证</div><div class="pb-group">${linkSteps}</div>` : ""}
                ${attSteps ? `<div class="email-sub-label">附件验证</div><div class="pb-group">${attSteps}</div>` : ""}` : ""}
            </div>
        </div>`;
}

// ---- 链接沙箱验证结果 (report.sandbox_link_verdicts / 超时 link_report) ----
// replace 模式: report 事件全量渲染 (标题+卡); append 模式: link_report 超时后补,
// 只追加卡 — 覆写会把 report 已渲染的验证卡抹掉 (review 发现的 UI 覆写 bug)
function renderLinkVerdicts(verdicts, mode = "replace") {
    const host = document.getElementById("email-link-verdicts");
    if (!host || !verdicts.length) return;
    if (mode === "append" && host.innerHTML) {
        host.insertAdjacentHTML("beforeend", _linkVerdictCards(verdicts));
        return;
    }
    host.innerHTML = `
        <h4 class="email-sec-title">链接沙箱验证 <span class="t-dim">urlscan 代访, 本机零接触 — 含 DOM 表单检测与视觉仿冒判定, 结论为概率性线索</span></h4>
        ${_linkVerdictCards(verdicts)}`;
}

// 卡片片段生成 (badge 闭包随 renderLinkVerdicts 之外不可用, 一并内聚在此)
function _linkVerdictCards(verdicts) {
    const badge = (v) => {
        const j = v.judgement || {};
        // 语义判定优先于 urlscan score — 合法域下的仿冒页 score=0 也能亮红
        if (j.impersonation === "impersonating") return `<span class="lv-badge lv-malicious">沙箱判定 · 仿冒${j.impersonation_target && j.impersonation_target !== "无" ? " " + escapeHtml(j.impersonation_target) : ""}</span>`;
        if (v.status === "verified" && v.malicious === true) return `<span class="lv-badge lv-malicious">已验证 · 恶意</span>`;
        if ((v.form || {}).has_password) return `<span class="lv-badge lv-pwform">含密码表单</span>`;
        if (v.status === "verified") return `<span class="lv-badge lv-clean">已验证 · 干净</span>`;
        if (v.status === "skipped") {
            // 两种跳过: 内网地址沙箱不可达 / 等待窗超时被取消
            const reach = (v.error || "").includes("不可达") ? "沙箱不可达" : "超时未参与";
            return `<span class="lv-badge lv-skip">${reach}</span>`;
        }
        return `<span class="lv-badge lv-error">验证失败</span>`;
    };
    return verdicts.map((v) => {
        const det = [];
        const j = v.judgement || {};
        const form = v.form || {};
        if (j.claimed_identity) det.push(`页面声称: ${j.claimed_identity}`);
        if (form.has_password === true) det.push(`密码表单: 有${form.action_domain ? ` · 提交至 ${form.cross_domain ? "(异域) " : "(同域) "}${form.action_domain}` : ""}`);
        else if (form.has_password === false) det.push("密码表单: 无");
        if (j.impersonation && j.impersonation !== "unclear") det.push(`视觉判定: ${j.impersonation}${j.reasoning ? ` — ${j.reasoning}` : ""}${typeof j.confidence === "number" ? ` (${(j.confidence * 100).toFixed(0)}%)` : ""}`);
        if (v.final_url && v.final_url !== v.url) det.push(`落地 URL: ${v.final_url}`);
        if (typeof v.score === "number") det.push(`urlscan 评分: ${v.score}`);
        if ((v.categories || []).length) det.push(`类别: ${v.categories.join(", ")}`);
        if (typeof v.domain_age_days === "number") det.push(`域名年龄: ${v.domain_age_days} 天`);
        if (v.error) det.push(`说明: ${v.error}`);
        // 截图链接只放行 urlscan.io 域 (固定 https 前缀校验)
        const shotOk = /^https:\/\/urlscan\.io\//.test(v.screenshot || "");
        return `<div class="lv-card">
            <div class="lv-head">${badge(v)}<span class="lv-url mono">${escapeHtml(v.url || "")}</span></div>
            ${det.length ? `<details class="lv-detail"><summary>详情</summary><div class="mono">${escapeHtml(det.join("\n"))}</div></details>` : ""}
            ${shotOk ? `<div class="lv-shot"><a href="${escapeHtml(v.screenshot)}" target="_blank" rel="noopener noreferrer">沙箱截图 ↗</a></div>` : ""}
        </div>`;
    }).join("");
}

// ---- 启动: 文本入口 ----
async function startEmailTriage() {
    const raw = document.getElementById("email-raw").value.trim();
    if (!raw) {
        emailStatus("请先粘贴邮件原文");
        return;
    }
    const note = document.getElementById("email-note").value.trim();
    emailReset();
    emailStage("transcribe", "skip");   // 文本入口无转写阶段
    setEmailRunning(true);
    emailAbort = new AbortController();
    try {
        const resp = await fetch(`${API}/secops/email/triage`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: `email-web-${Date.now()}`,
                raw_email: raw,
                note,
            }),
            signal: emailAbort.signal,
        });
        await consumeEmailSSE(resp, handleEmailEvent);
    } catch (e) {
        if (e.name === "AbortError") emailStatus("已停止");
        else {
            emailStatus("失败 ✗");
            emailFinding(`<span class="f-tag tag-error">错误</span> ${escapeHtml(e.message)}`);
        }
    } finally {
        setEmailRunning(false);
    }
}

// ---- 启动: 截图入口 (视觉转写 → 同一管线) ----
async function startEmailImage(file) {
    const note = document.getElementById("email-note").value.trim();
    emailReset();
    emailStatus("上传校验中…");
    setEmailRunning(true);
    emailAbort = new AbortController();
    try {
        const b64 = await new Promise((resolve, reject) => {
            const fr = new FileReader();
            fr.onload = () => resolve(String(fr.result).split(",")[1] || "");
            fr.onerror = () => reject(new Error("截图读取失败"));
            fr.readAsDataURL(file);
        });
        const resp = await fetch(`${API}/secops/email/triage/image`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ image_b64: b64, mime: file.type || "image/png", note }),
            signal: emailAbort.signal,
        });
        await consumeEmailSSE(resp, handleEmailEvent);
    } catch (e) {
        if (e.name === "AbortError") emailStatus("已停止");
        else {
            emailStatus("失败 ✗");
            emailFinding(`<span class="f-tag tag-error">错误</span> ${escapeHtml(e.message)}`);
        }
    } finally {
        setEmailRunning(false);
    }
}

function setEmailRunning(running) {
    document.getElementById("email-start").disabled = running;
    document.getElementById("email-stop").disabled = !running;
    // 截图入口一并禁用 — 运行中再上传会与进行中的 SSE 并发交错写同一 DOM,
    // 且 emailAbort 被覆盖后"停止"只能停后一路 (review 发现的 UI 竞态)
    document.getElementById("email-img-input").disabled = running;
}

// ---- 事件绑定 ----
document.getElementById("email-start").addEventListener("click", startEmailTriage);
document.getElementById("email-stop").addEventListener("click", () => {
    if (emailAbort) emailAbort.abort();
});
document.getElementById("email-img-input").addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    e.target.value = "";   // 允许连续上传同一张
    if (file) startEmailImage(file);
});

// 剧本命令复制 (事件委托 — 命令经 data-cmd 传递, dataset 读出即还原)
document.getElementById("secops-email-report").addEventListener("click", async (e) => {
    const btn = e.target.closest(".pb-copy");
    if (!btn) return;
    try {
        await navigator.clipboard.writeText(btn.dataset.cmd || "");
        btn.textContent = "已复制";
        setTimeout(() => (btn.textContent = "复制"), 2000);
    } catch { /* 剪贴板不可用时静默 */ }
});
