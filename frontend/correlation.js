// ============================================================
// 关联研判 (Correlation Chat) — 聊天式累积告警 → 关联报告
// 事件: corr_alert_added / corr_tool_call / corr_assistant / corr_report / corr_error
// ============================================================
let corrCid = null;            // 当前关联会话 id
let corrTurns = 0;             // 已完成轮数 (≥1 才亮「生成报告」)
let corrAbort = null;          // AbortController
let corrReportMd = "";         // 最近报告的 markdown 源 (导出/复制用)
let corrDispTarget = "";       // 处置登记目标: "single" 或 corrCid

// --- 模式切换 (双态) ---
function switchSecopsMode(mode) {
    const single = document.getElementById("secops-mode-single");
    const corr = document.getElementById("secops-mode-corr");
    const corrWrap = document.getElementById("secops-corr-wrap");
    const isCorr = mode === "corr";
    single.classList.toggle("on", !isCorr);
    single.setAttribute("aria-pressed", String(!isCorr));
    corr.classList.toggle("on", isCorr);
    corr.setAttribute("aria-pressed", String(isCorr));
    corrWrap.classList.toggle("hidden", !isCorr);
}
document.getElementById("secops-mode-single").addEventListener("click", () => switchSecopsMode("single"));
document.getElementById("secops-mode-corr").addEventListener("click", () => switchSecopsMode("corr"));

// --- 聊天流渲染 ---
function corrAppend(html, cls = "msg msg-ai") {
    const msgs = document.getElementById("secops-corr-messages");
    if (!msgs) return;
    const ph = msgs.querySelector(".placeholder");
    if (ph) ph.remove();
    const div = document.createElement("div");
    div.className = cls;
    div.innerHTML = `<div class="msg-content">${html}</div>`;
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;
    return div;
}

function corrToolCard(name, args, result) {
    return `<details class="corr-tool"><summary><span class="f-tag tag-scout">工具</span> ${escapeHtml(name)} <span class="t-dim">${escapeHtml(String(args).slice(0, 90))}</span></summary><pre class="corr-tool-result">${escapeHtml(String(result || "(无)"))}</pre></details>`;
}

// --- 发送一轮 (SSE 流式消费) ---
async function sendCorrMsg() {
    const input = document.getElementById("secops-corr-input");
    const text = input.value.trim();
    if (!text) return;
    input.value = "";
    corrAppend(escapeHtml(text).replace(/\n/g, "<br>"), "msg msg-user");

    const statusEl = document.getElementById("secops-corr-status");
    const sendBtn = document.getElementById("secops-corr-send");
    statusEl.textContent = "关联分析中…";
    sendBtn.disabled = true;
    corrAbort = new AbortController();
    const t0 = performance.now();
    let llmCalls = 0;

    try {
        const resp = await fetch(`${API}/secops/correlation`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ cid: corrCid || "", message: text }),
            signal: corrAbort.signal,
        });
        if (!resp.ok) {
            const e = await resp.json().catch(() => ({}));
            throw new Error(e.detail || `HTTP ${resp.status}`);
        }
        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buf = "";
        for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            buf += decoder.decode(value, { stream: true });
            let idx;
            while ((idx = buf.indexOf("\n")) >= 0) {
                const line = buf.slice(0, idx).trim();
                buf = buf.slice(idx + 1);
                if (!line.startsWith("data: ")) continue;
                let ev = null;
                try { ev = JSON.parse(line.slice(6)); } catch { continue; }
                const t = ev.type, d = ev.data || {};
                if (d.cid) corrCid = d.cid; // 任意事件带 cid 即兜底持有
                if (t === "corr_alert_added") {
                    corrAppend(`<span class="f-tag tag-triage">收录</span> 第 ${d.alert_index + 1} 条告警已入会话 <span class="t-dim">${escapeHtml(String(d.raw || "").slice(0, 120))}</span>`, "msg msg-sys");
                } else if (t === "corr_tool_call") {
                    llmCalls += 0; // 工具事件不计 LLM; llm_calls 由 corr_assistant 带
                    corrAppend(corrToolCard(d.name, JSON.stringify(d.args || {}), d.result), "msg msg-tool");
                } else if (t === "corr_assistant") {
                    corrTurns += 1;
                    document.getElementById("secops-corr-report-btn").disabled = false;
                    const a = d.answer || d; // 模块层嵌套 {answer}, API 层平铺 — 两边都兼容
                    const pts = (a.correlation_points || []).map((p) => `<li>${escapeHtml(p)}</li>`).join("");
                    const hints = (a.next_hints || []).map((h) => `<li>${escapeHtml(h)}</li>`).join("");
                    corrAppend(
                        `${escapeHtml(a.summary || "")}` +
                        (pts ? `<div class="corr-pts"><span class="t-dim">本轮关联点:</span><ul>${pts}</ul></div>` : "") +
                        (hints ? `<div class="corr-pts"><span class="t-dim">建议下一步:</span><ul>${hints}</ul></div>` : ""),
                    );
                    const cost = document.getElementById("secops-corr-cost");
                    cost.classList.remove("hidden");
                    cost.textContent = `耗时 ${((performance.now() - t0) / 1000).toFixed(1)}s · LLM 调用 ${d.llm_calls ?? "—"} 次`;
                    statusEl.textContent = "就绪 — 可继续粘贴下一条告警, 或生成关联报告";
                } else if (t === "corr_error") {
                    corrAppend(`<span class="f-tag tag-critic">异常</span> ${escapeHtml(d.message || "")}`, "msg msg-sys");
                }
            }
        }
    } catch (e) {
        if (e.name !== "AbortError") corrAppend(`发送失败: ${escapeHtml(e.message)}`, "msg msg-sys");
        statusEl.textContent = "就绪";
    } finally {
        sendBtn.disabled = false;
    }
}

// --- 生成关联报告 ---
async function generateCorrReport() {
    if (!corrCid || !corrTurns) return;
    const btn = document.getElementById("secops-corr-report-btn");
    const statusEl = document.getElementById("secops-corr-status");
    btn.disabled = true;
    statusEl.textContent = "汇总攻击链生成关联报告…";
    corrAppend("<span class=\"f-tag tag-analyst\">报告</span> 正在汇总会话内全部告警与调查发现…", "msg msg-sys");
    try {
        const resp = await fetch(`${API}/secops/correlation/${encodeURIComponent(corrCid)}/report`, {
            method: "POST",
            headers: { "Accept": "application/json" },
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
        renderCorrReport(data.report || data);
        statusEl.textContent = "关联报告已生成";
        corrAppend("<span class=\"f-tag tag-analyst\">报告</span> 关联报告已生成, 见下方报告区", "msg msg-sys");
    } catch (e) {
        corrAppend(`生成失败: ${escapeHtml(e.message)}`, "msg msg-sys");
        statusEl.textContent = "就绪";
    } finally {
        btn.disabled = false;
    }
}

// --- 报告渲染 (attack_chain 时间线 + correlations 卡片) ---
function renderCorrReport(r) {
    const el = document.getElementById("secops-corr-report");
    const actions = document.getElementById("secops-corr-report-actions");
    el.classList.remove("hidden");
    actions.classList.remove("hidden");
    const chain = (r.attack_chain || []).map((s, i) => `<li><span class="chain-step">${i + 1}</span> ${escapeHtml(s)}</li>`).join("");
    const corrs = (r.correlations || []).map((c) => `<div class="corr-card"><div class="corr-card-title">告警 ${((c.alerts_involved || []).map((n) => n + 1).join(" ↔ "))} — ${escapeHtml(c.link || "")}</div></div>`).join("");
    const evs = (r.key_evidence || []).map((e) => `<li>${escapeHtml(e)}</li>`).join("");
    const acts = (r.response_actions || []).map((a) => `<li>${escapeHtml(a)}</li>`).join("");
    const mitre = (r.mitre || []).map((m) => `<span class="mitre-chip">${escapeHtml(m)}</span>`).join(" ");
    el.innerHTML = `
        <h3>关联研判报告 <span class="verdict-badge">${VERDICT_LABEL[r.verdict]?.text || r.verdict || "?"}</span> <span class="t-dim">${escapeHtml(r.severity || "")} · 置信度 ${typeof r.confidence === "number" ? (r.confidence * 100).toFixed(0) + "%" : "—"}</span></h3>
        ${chain ? `<div class="corr-section"><h4>攻击链</h4><ol class="chain-list">${chain}</ol></div>` : ""}
        ${corrs ? `<div class="corr-section"><h4>告警关联</h4>${corrs}</div>` : ""}
        ${mitre ? `<div class="corr-section"><h4>MITRE ATT&CK</h4>${mitre}</div>` : ""}
        ${evs ? `<div class="corr-section"><h4>关键证据</h4><ul>${evs}</ul></div>` : ""}
        ${acts ? `<div class="corr-section"><h4>处置建议</h4><ul>${acts}</ul></div>` : ""}
        ${r.conclusion ? `<div class="corr-section"><h4>结论</h4><p>${escapeHtml(r.conclusion)}</p></div>` : ""}
    `;
    // markdown 源 (复制/导出)
    corrReportMd = [
        `# 关联研判报告 (${corrCid})`, "",
        `- 判定: ${r.verdict} · ${r.severity} · 置信度 ${r.confidence}`, "",
        r.attack_chain?.length ? `## 攻击链\n${r.attack_chain.map((s, i) => `${i + 1}. ${s}`).join("\n")}\n` : "",
        r.correlations?.length ? `## 告警关联\n${r.correlations.map((c) => `- 告警 ${(c.alerts_involved || []).map((n) => n + 1).join("↔")}: ${c.link}`).join("\n")}\n` : "",
        r.mitre?.length ? `## MITRE\n${r.mitre.join(", ")}\n` : "",
        r.key_evidence?.length ? `## 关键证据\n${r.key_evidence.map((e) => `- ${e}`).join("\n")}\n` : "",
        r.response_actions?.length ? `## 处置建议\n${r.response_actions.map((a) => `- ${a}`).join("\n")}\n` : "",
        r.conclusion ? `## 结论\n${r.conclusion}\n` : "",
    ].join("\n");
}

// --- 复制 / 导出 .md ---
document.getElementById("secops-corr-copy").addEventListener("click", async () => {
    if (!corrReportMd) return;
    try {
        await navigator.clipboard.writeText(corrReportMd);
        document.getElementById("secops-corr-disp-result").textContent = "已复制到剪贴板";
        setTimeout(() => (document.getElementById("secops-corr-disp-result").textContent = ""), 2500);
    } catch { /* 剪贴板不可用时静默 */ }
});
document.getElementById("secops-corr-export").addEventListener("click", () => {
    if (!corrReportMd) return;
    const blob = new Blob([corrReportMd], { type: "text/markdown;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `secops-correlation-${corrCid || "report"}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
});

// --- 发送按钮/回车 ---
document.getElementById("secops-corr-send").addEventListener("click", sendCorrMsg);
document.getElementById("secops-corr-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.isComposing) sendCorrMsg();
});
document.getElementById("secops-corr-report-btn").addEventListener("click", generateCorrReport);

// ============================================================
// 处置登记 (单条研判 + 关联报告共用)
// ============================================================
// 处置动作 → 后端枚举 (resolved/false_positive/deferred)
const DISP_ACTION_MAP = { "已处置": "resolved", "误报": "false_positive", "搁置": "deferred" };

async function submitDisposition(action, resultEl, target) {
    try {
        const body = { action: DISP_ACTION_MAP[action] || action, note: "" };
        const url = target === "corr"
            ? `${API}/secops/correlation/${encodeURIComponent(corrCid)}/disposition`
            : `${API}/secops/${encodeURIComponent(lastSecopsSessionId || "")}/disposition`;
        const resp = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
        resultEl.textContent = `已登记: ${action}`;
    } catch (e) {
        resultEl.textContent = `登记失败: ${e.message}`;
    }
}

// 单条研判报告区三按钮
document.querySelectorAll("#secops-disposition .disp-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
        submitDisposition(btn.dataset.action, document.getElementById("secops-disp-result"), "single");
    });
});
// 关联报告区三按钮
document.querySelectorAll(".corr-disp").forEach((btn) => {
    btn.addEventListener("click", () => {
        submitDisposition(btn.dataset.action, document.getElementById("secops-corr-disp-result"), "corr");
    });
});
