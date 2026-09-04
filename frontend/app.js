// ============================================================
// Multi-Agent AIOps Platform - Frontend Logic
// ============================================================

const API = "/api/v1";

// ---------- 主题切换 (亮/暗) ----------
const THEME_KEY = "aiops_theme";
function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem(THEME_KEY, theme);
    // 按钮状态同步: 亮色 = 按下 (当前显示月亮, 点击切回暗色)
    const btn = document.getElementById("theme-toggle");
    if (btn) btn.setAttribute("aria-pressed", String(theme === "light"));
}
(function initTheme() {
    const saved = localStorage.getItem(THEME_KEY) || "dark";
    applyTheme(saved);
    const btn = document.getElementById("theme-toggle");
    if (btn) btn.addEventListener("click", () => {
        applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
    });
})();

// ---------- Tab 切换 ----------
document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
        document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("tab-active"));
        document.querySelectorAll(".tab-pane").forEach((p) => p.classList.add("hidden"));
        btn.classList.add("tab-active");
        const tab = btn.dataset.tab;
        document.getElementById(`tab-${tab}`).classList.remove("hidden");
        if (tab === "documents") loadDocs();
    });
});

// ---------- 健康检查 ----------
async function checkHealth() {
    try {
        const r = await fetch(`${API}/health/ready`);
        const data = await r.json();
        const ready = data?.data?.status === "ready";
        const milvusOk = data?.data?.dependencies?.milvus?.status === "ok";
        const mcpOk = data?.data?.dependencies?.mcp?.status === "ok";
        const dot = document.getElementById("health-dot");
        const text = document.getElementById("health-text");
        if (ready && mcpOk) {
            dot.className = "w-3 h-3 rounded-full bg-green-400";
            text.textContent = `就绪 · MCP ${data.data.dependencies.mcp.tools_count} 工具`;
        } else if (ready) {
            dot.className = "w-3 h-3 rounded-full bg-yellow-400";
            text.textContent = "就绪 · MCP 未连";
        } else {
            dot.className = "w-3 h-3 rounded-full bg-red-500";
            text.textContent = "Milvus 不可用";
        }
    } catch (e) {
        document.getElementById("health-text").textContent = "服务不可达";
    }
}
checkHealth();
setInterval(checkHealth, 15000);

// ============================================================
// Skill 列表 (页面加载时拉一次, 后续诊断时高亮选中项)
// ============================================================
const RISK_BADGE = {
    low:    { color: "bg-emerald-100 text-emerald-700 border-emerald-200", label: "低风险" },
    medium: { color: "bg-amber-100 text-amber-700 border-amber-200",       label: "中风险" },
    high:   { color: "bg-red-100 text-red-700 border-red-200",             label: "高风险" },
};

async function loadSkills() {
    const listEl = document.getElementById("skill-list");
    const countEl = document.getElementById("skill-count");
    try {
        const r = await fetch(`${API}/skills`);
        const data = await r.json();
        if (data?.code !== "SUCCESS") throw new Error(data?.message || "加载 Skill 失败");
        const skills = data?.data?.skills || [];
        countEl.textContent = `· ${skills.length} 个`;

        if (skills.length === 0) {
            listEl.innerHTML = '<span class="text-slate-400 italic col-span-full">暂无 Skill 注册</span>';
            return;
        }

        listEl.innerHTML = "";
        skills.forEach((s) => {
            const card = document.createElement("div");
            card.className = "skill-card";
            card.dataset.skillName = s.name;
            card.title = `${s.display_name || s.name} · ${s.risk_level || "low"}`;
            card.innerHTML = `
                <div class="sk-name truncate">${escapeHtml(s.display_name)}</div>
                <div class="sk-id truncate">${escapeHtml(s.name)}</div>
            `;
            listEl.appendChild(card);
        });
    } catch (e) {
        listEl.innerHTML = `<span class="text-red-500 col-span-full">加载失败: ${escapeHtml(e.message)}</span>`;
    }
}
loadSkills();

function highlightSkill(skillName, reason, append = false) {
    if (!append) {
        // 清除旧的高亮
        document.querySelectorAll(".skill-card.skill-active").forEach((el) => el.classList.remove("skill-active"));
    }

    const card = document.querySelector(`.skill-card[data-skill-name="${CSS.escape(skillName || "")}"]`);
    const banner = document.getElementById("skill-selected-banner");
    const nameEl = document.getElementById("skill-selected-name");
    const reasonEl = document.getElementById("skill-reason");

    if (card) {
        card.classList.add("skill-active");
        card.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "nearest" });
        const displayName = card.querySelector(".font-semibold")?.textContent || skillName;
        if (append && nameEl.textContent && nameEl.textContent !== "(未知)") {
            if (!nameEl.textContent.includes(displayName)) {
                nameEl.textContent += " + " + displayName;
            }
        } else {
            nameEl.textContent = displayName;
        }
    } else if (!append) {
        nameEl.textContent = skillName || "(未知)";
    }
    banner.classList.remove("hidden");

    reasonEl.textContent = "";
    reasonEl.classList.add("hidden");
}

function clearSkillHighlight() {
    document.querySelectorAll(".skill-card.skill-active").forEach((el) => el.classList.remove("skill-active"));
    document.getElementById("skill-selected-banner").classList.add("hidden");
    document.getElementById("skill-reason").classList.add("hidden");
}

// ============================================================
// AIOps 诊断
// ============================================================
let aiopsAbortController = null;
let currentSessionId = "";

// ---- Agent 执行轨迹收集 (流程图数据源) ----
const aiopsTrace = {
    steps: [],      // {iter, step, tools: [{name, args, result, elapsed, status}], preview}
    current: null,  // 正在执行的步骤
    reset() { this.steps = []; this.current = null; },
    ensureStep(iter, stepName) {
        let s = this.steps.find((x) => x.iter === iter);
        if (!s) { s = { iter, step: stepName || "", tools: [], preview: "" }; this.steps.push(s); }
        if (stepName && !s.step) s.step = stepName;
        this.current = s;
        return s;
    },
    addTool(ev) {
        const s = this.current || this.ensureStep(0, "");
        s.tools.push({
            name: ev.name, args: ev.args || "", result: ev.result_preview || "",
            elapsed: ev.elapsed_ms, status: ev.status,
        });
    },
};

function renderTrace() {
    const wrap = document.getElementById("aiops-trace");
    const tl = document.getElementById("trace-timeline");
    if (!wrap || !tl) return;
    if (!aiopsTrace.steps.length) { wrap.classList.add("hidden"); return; }
    tl.innerHTML = "";

    const reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // ---- 布局常量 (与 styles.css 中节点尺寸保持一致) ----
    const STEP_W = 190, STEP_H = 40;                       // 步骤节点
    const TOOL_W = 150, TOOL_H = 28, TOOL_GAP = 6;         // 工具子节点
    const PILL_W = 84, PILL_H = 36;                        // 开始/报告 胶囊
    const PLAN_W = 170, PLAN_H = 48;                       // Planner 节点
    const ORCH_W = 150, ORCH_H = 44;                       // 编排 (选派专家) 节点
    const COL_GAP = 70, TOOL_COL_GAP = 46, ROW_GAP = 14;   // 列距 / 步骤纵距

    // 0. 拆出编排伪步骤: skills_selected 写入的 iter=0 无工具条目只是选派专家,
    //    独立渲染在 开始 与 Planner 之间的编排列; iter=0 但带工具的是真实执行, 仍按普通步骤布局
    const orchStep = aiopsTrace.steps.find((s) => s.iter === 0 && !s.tools.length) || null;

    // 1. 纵向布局: 每个步骤占一个"块", 块高 = max(步骤节点高, 工具栈高), 避免工具互相压叠
    //    idx 保留在 aiopsTrace.steps 中的原始下标, 工具芯片点击回查数据时要用
    const blocks = aiopsTrace.steps
        .map((s, idx) => {
            const toolsH = s.tools.length ? TOOL_H * s.tools.length + TOOL_GAP * (s.tools.length - 1) : 0;
            return { idx, step: s, h: Math.max(STEP_H, toolsH + 6) };
        })
        .filter((b) => b.step !== orchStep);
    const contentH = blocks.reduce((n, b) => n + b.h, 0) + (blocks.length ? ROW_GAP * (blocks.length - 1) : 0);

    // 2. 横向列: 开始 → (选派专家) → Planner → 步骤 → 工具子列 → 报告
    const xStart = 0;
    const xOrch = xStart + PILL_W + COL_GAP;               // 编排列, 仅 orchStep 存在时占用
    const xPlan = orchStep ? xOrch + ORCH_W + COL_GAP : xStart + PILL_W + COL_GAP;
    const xStep = xPlan + PLAN_W + COL_GAP;
    const xTool = xStep + STEP_W + TOOL_COL_GAP;
    const hasTools = blocks.some((b) => b.step.tools.length);
    // 退化场景: 计划未生成 (blocks 为空) 时不画 Planner, 报告紧跟选派专家
    const xEnd = blocks.length
        ? (hasTools ? xTool + TOOL_W : xStep + STEP_W) + COL_GAP
        : xOrch + ORCH_W + COL_GAP;
    const canvasW = xEnd + PILL_W;
    const canvasH = Math.max(contentH, PLAN_H);
    const midY = canvasH / 2;

    // 3. 画布 + 连线层 (SVG 垫在节点下方)
    const canvas = document.createElement("div");
    canvas.className = "trace-canvas";
    canvas.style.width = `${canvasW}px`;
    canvas.style.height = `${canvasH}px`;
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "trace-svg");
    svg.setAttribute("width", String(canvasW));
    svg.setAttribute("height", String(canvasH));
    canvas.appendChild(svg);
    tl.appendChild(canvas);

    const edgePaths = [];
    const bez = (x1, y1, x2, y2) =>
        `M ${x1} ${y1} C ${x1 + 32} ${y1}, ${x2 - 32} ${y2}, ${x2} ${y2}`;
    const nodes = [];
    const addNode = (el, x, y, w, h) => {
        el.style.left = `${x}px`; el.style.top = `${y}px`;
        el.style.width = `${w}px`; el.style.height = `${h}px`;
        canvas.appendChild(el);
        nodes.push(el);
    };
    const mk = (cls, html) => {
        const el = document.createElement("div");
        el.className = cls;
        el.innerHTML = html;
        return el;
    };

    // 4. 枢纽节点: 开始 / 编排 / Planner, 纵向居中于画布 (无执行步骤时 Planner 不出现)
    const totalTools = blocks.reduce((n, b) => n + b.step.tools.length, 0);
    addNode(mk("dag-node dag-start", "开始"), xStart, midY - PILL_H / 2, PILL_W, PILL_H);
    if (orchStep) {
        // 去掉 "Orchestrator 选派专家:" 前缀只留专家名; 无该前缀时整段原文展示
        const names = orchStep.step.replace(/^Orchestrator 选派专家:\s*/, "") || "选派专家";
        const orchEl = mk("dag-node dag-orch",
            `<div class="dag-orch-label">Orchestrator</div>
             <div class="dag-orch-names">${escapeHtml(names)}</div>`);
        orchEl.title = orchStep.step;  // 名单超宽截断后靠 title 看全文
        addNode(orchEl, xOrch, midY - ORCH_H / 2, ORCH_W, ORCH_H);
        edgePaths.push(bez(xStart + PILL_W, midY, xOrch, midY));
    }
    if (blocks.length) {
        addNode(
            mk("dag-node dag-planner",
                `<div class="dag-planner-title">Planner</div>
                 <div class="dag-planner-sub">计划 ${blocks.length} 步 · ${totalTools} 工具</div>`),
            xPlan, midY - PLAN_H / 2, PLAN_W, PLAN_H
        );
        edgePaths.push(bez(orchStep ? xOrch + ORCH_W : xStart + PILL_W, midY, xPlan, midY));
    }

    // 5. 步骤节点纵向铺开, 从 Planner 扇出; 各自的工具子节点挂在右侧子列, 最终汇入报告
    let yCur = 0;
    blocks.forEach((b) => {
        const s = b.step;
        const cy = yCur + STEP_H / 2;
        const title = s.step || `步骤 ${s.iter}`;
        const stepEl = mk("dag-node dag-step",
            `<span class="dag-step-num">${escapeHtml(String(s.iter))}</span>
             <span class="dag-step-title">${escapeHtml(title)}</span>`);
        stepEl.title = title;  // 超宽截断后靠 title 看全文
        addNode(stepEl, xStep, yCur, STEP_W, STEP_H);
        edgePaths.push(bez(xPlan + PLAN_W, midY, xStep, cy));

        // 工具子节点: 首个与步骤节点顶对齐, 之后向下紧凑堆叠
        let ty = yCur + 6;
        let srcX = xStep + STEP_W, srcY = cy;   // 无工具的步骤直接从自身右侧汇入报告
        s.tools.forEach((t, ti) => {
            const tcy = ty + TOOL_H / 2;
            const btn = document.createElement("button");
            btn.className = `trace-tool ${t.status === "ok" ? "ok" : "fail"}`;
            btn.dataset.step = String(b.idx);  // 用原始下标, 点击时才能回查到 aiopsTrace.steps 对应条目
            btn.dataset.tool = String(ti);
            btn.innerHTML = `
                <span class="trace-tool-icon">${t.status === "ok" ? "✓" : "✗"}</span>
                <span class="trace-tool-name">${escapeHtml(t.name)}</span>
                <span class="trace-tool-ms">${t.elapsed != null ? t.elapsed + "ms" : ""}</span>`;
            addNode(btn, xTool, ty, TOOL_W, TOOL_H);
            edgePaths.push(bez(xStep + STEP_W, cy, xTool, tcy));
            srcX = xTool + TOOL_W; srcY = tcy;
            ty += TOOL_H + TOOL_GAP;
        });
        edgePaths.push(bez(srcX, srcY, xEnd, midY));
        yCur += b.h + ROW_GAP;
    });

    // 6. 报告节点 (退化场景下由选派专家直接汇入, 不经过 Planner)
    addNode(mk("dag-node dag-end", "报告"), xEnd, midY - PILL_H / 2, PILL_W, PILL_H);
    if (orchStep && !blocks.length) edgePaths.push(bez(xOrch + ORCH_W, midY, xEnd, midY));

    // 7. 连线: 节点入场后描线 (stroke-dashoffset 过渡), reduced-motion 时跳过由 CSS 兜底
    edgePaths.forEach((d, i) => {
        const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
        p.setAttribute("d", d);
        svg.appendChild(p);
        if (reduced) return;
        const len = p.getTotalLength();
        p.style.strokeDasharray = String(len);
        p.style.strokeDashoffset = String(len);
        p.getBoundingClientRect();  // 强制回流, 让初始 dashoffset 先生效再触发过渡
        p.style.transition = `stroke-dashoffset .3s var(--ease-out) ${120 + i * 15}ms`;
        p.style.strokeDashoffset = "0";
    });

    // 8. 节点入场错峰: 每个节点延迟 40ms (动画本体在 CSS dagNodeIn)
    if (!reduced) nodes.forEach((el, i) => { el.style.animationDelay = `${i * 40}ms`; });

    // 9. 工具节点点击 → 画布下方展开 输入/输出 详情 (同时只开一个, 再点同一个收起)
    let openedKey = "";
    canvas.addEventListener("click", (e) => {
        const btn = e.target.closest(".trace-tool");
        if (!btn) return;
        const step = aiopsTrace.steps[Number(btn.dataset.step)];
        const tool = step && step.tools[Number(btn.dataset.tool)];
        if (!tool) return;
        const key = `${btn.dataset.step}:${btn.dataset.tool}`;
        let detail = tl.querySelector(".trace-detail");
        if (detail && openedKey === key) { detail.remove(); openedKey = ""; return; }
        if (!detail) {
            detail = document.createElement("div");
            detail.className = "trace-detail";
            tl.appendChild(detail);
        }
        detail.innerHTML = `
            <div class="trace-detail-block"><div class="trace-detail-label">输入</div><pre>${escapeHtml(tool.args || "(无)")}</pre></div>
            <div class="trace-detail-block"><div class="trace-detail-label">输出</div><pre>${escapeHtml(tool.result || "(无)")}</pre></div>`;
        openedKey = key;
    });

    wrap.classList.remove("hidden");
}

document.getElementById("aiops-start").addEventListener("click", startAiops);
document.getElementById("aiops-stop").addEventListener("click", () => {
    if (aiopsAbortController) aiopsAbortController.abort();
});

// 监控面板状态
const aiopsMonitor = {
    startTs: 0,
    timer: null,
    toolCount: 0,
    toolFail: 0,
    tokenCount: 0,           // 字符流粗估 (流过来即累加)
    realInputTokens: 0,      // LLM usage 真实 input
    realOutputTokens: 0,     // LLM usage 真实 output
    realTotalTokens: 0,
    cacheHitTokens: 0,       // DeepSeek 才有
    cacheMissTokens: 0,
    hasRealUsage: false,
    reset() {
        this.startTs = Date.now();
        this.toolCount = 0;
        this.toolFail = 0;
        this.tokenCount = 0;
        this.realInputTokens = 0;
        this.realOutputTokens = 0;
        this.realTotalTokens = 0;
        this.cacheHitTokens = 0;
        this.cacheMissTokens = 0;
        this.hasRealUsage = false;
        setText("mon-step", "—");
        setText("mon-step-label", "Orchestrator 评估中...");
        setText("mon-elapsed", "0.0s");
        setText("mon-tools", "0");
        setText("mon-tools-fail", "失败 0");
        setText("mon-tokens", "0");
        setText("mon-tokens-detail", "输入 0 · 输出 0");
        setText("mon-tokens-badge", "~估算");
        setText("mon-stream-hint", "等待中");
        document.getElementById("mon-stream").innerHTML =
            '<span class="text-slate-400 italic">诊断开始后, 模型生成的文本会实时显示在此...</span>';
        document.getElementById("mon-tool-feed").innerHTML =
            '<span class="text-slate-400 italic px-2">暂无工具调用</span>';
        if (this.timer) clearInterval(this.timer);
        this.timer = setInterval(() => {
            const s = ((Date.now() - this.startTs) / 1000).toFixed(1);
            setText("mon-elapsed", `${s}s`);
        }, 100);
    },
    stop() {
        if (this.timer) {
            clearInterval(this.timer);
            this.timer = null;
        }
    },
};

function setText(id, v) {
    const el = document.getElementById(id);
    if (el) el.textContent = v;
}

function showAiopsReport() {
    document.getElementById("aiops-monitor").classList.add("hidden");
    const rep = document.getElementById("aiops-report");
    rep.classList.remove("hidden");
    setText("aiops-right-title", "诊断报告");
}

function showAiopsMonitor() {
    document.getElementById("aiops-monitor").classList.remove("hidden");
    document.getElementById("aiops-report").classList.add("hidden");
    setText("aiops-right-title", "📊 诊断监控");
}

async function startAiops() {
    const query = document.getElementById("aiops-query").value.trim();
    if (!query) return alert("请输入告警内容");

    // UI reset
    const planEl = document.getElementById("aiops-plan");
    const stepsEl = document.getElementById("aiops-steps");
    const reportEl = document.getElementById("aiops-report");
    const statusEl = document.getElementById("aiops-status");
    planEl.innerHTML = '<span class="placeholder">等待 Planner…</span>';
    stepsEl.innerHTML = "";
    reportEl.innerHTML = "";
    showAiopsMonitor();
    aiopsMonitor.reset();
    aiopsTrace.reset();
    document.getElementById("aiops-trace").classList.add("hidden");
    statusEl.textContent = "Orchestrator 评估中…";
    clearSkillHighlight();

    document.getElementById("aiops-start").disabled = true;
    document.getElementById("aiops-stop").disabled = false;

    aiopsAbortController = new AbortController();
    currentSessionId = `web-${Date.now()}`;
    try {
        const resp = await fetch(`${API}/aiops/diagnose`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: currentSessionId, query }),
            signal: aiopsAbortController.signal,
        });
        await consumeSSE(resp, (ev) => handleAiopsEvent(ev, planEl, stepsEl, reportEl, statusEl));
        statusEl.textContent = "完成 ✓";
    } catch (e) {
        if (e.name === "AbortError") {
            statusEl.textContent = "已停止";
        } else {
            statusEl.textContent = "失败 ✗";
            showAiopsReport();
            reportEl.innerHTML = `<p class="text-red-500">错误: ${e.message}</p>`;
        }
    } finally {
        document.getElementById("aiops-start").disabled = false;
        document.getElementById("aiops-stop").disabled = true;
        aiopsAbortController = null;
        aiopsMonitor.stop();
    }
}

function handleAiopsEvent(ev, planEl, stepsEl, reportEl, statusEl) {
    const t = ev.type;
    const d = ev.data || {};
    // 诊断: 把所有 SSE 事件类型打到控制台, 方便排查监控为什么是 0
    if (t !== "transition") {
        console.log("[AIOps SSE]", t, d);
    }

    if (t === "start") {
        statusEl.textContent = "Orchestrator 评估中…";
    } else if (t === "skills_selected") {
        const skills = d.skills || [];
        // 清空现有的名字占位
        const nameEl = document.getElementById("skill-selected-name");
        if (nameEl) nameEl.textContent = "";

        skills.forEach((s, i) => highlightSkill(s, d.reason, i > 0));
        statusEl.textContent = `并行拉起专家: ${skills.join(', ') || "(无)"}, 会诊中…`;
        aiopsTrace.ensureStep(0, `Orchestrator 选派专家: ${skills.join(" + ")}`);
    } else if (t === "plan") {
        planEl.innerHTML = "";
        (d.plan || []).forEach((step, i) => {
            const div = document.createElement("div");
            div.className = "plan-row";
            div.innerHTML = `<span class="plan-num">${i + 1}</span><span>${escapeHtml(step)}</span>`;
            planEl.appendChild(div);
        });
        statusEl.textContent = `已生成 ${d.plan.length} 步计划`;
    } else if (t === "step_start") {
        // 创建 "executing" 卡片, 后续 step_token 往里追加流式内容
        let div = stepsEl.querySelector(`[data-step-iter="${d.iteration}"]`);
        if (!div) {
            div = document.createElement("div");
            div.className = "step-item executing";
            div.dataset.stepIter = String(d.iteration);
            div.innerHTML = `<div class="step-title">▶ 步骤 ${escapeHtml(String(d.iteration))}</div>
                <div class="step-desc">${escapeHtml(d.step || "")}</div>
                <div class="step-stream"></div>`;
            stepsEl.appendChild(div);
        }
        stepsEl.scrollTop = stepsEl.scrollHeight;
        statusEl.textContent = `正在执行第 ${d.iteration} 步…`;
        aiopsTrace.ensureStep(d.iteration, d.step);
        // 监控面板: 更新当前步骤 + 清空实时输出 (每步重置)
        setText("mon-step", String(d.iteration));
        setText("mon-step-label", (d.step || "").slice(0, 40));
        setText("mon-stream-hint", "生成中...");
        const stream = document.getElementById("mon-stream");
        if (stream) stream.textContent = "";
    } else if (t === "step_token") {
        const iter = d.iteration || 0;
        const content = d.content || "";
        let div = stepsEl.querySelector(`[data-step-iter="${iter}"]`);
        if (!div) {
            // 兜底: 没收到 step_start 就先建一张卡
            div = document.createElement("div");
            div.className = "step-item executing";
            div.dataset.stepIter = String(iter);
            div.innerHTML = `<div class="step-title">▶ 步骤 ${escapeHtml(String(iter))}</div>
                <div class="step-stream"></div>`;
            stepsEl.appendChild(div);
        }
        const stream = div.querySelector(".step-stream");
        if (stream) {
            stream.textContent += content;
            if (stream.textContent.length > 2000) {
                stream.textContent = "..." + stream.textContent.slice(-1800);
            }
        }
        stepsEl.scrollTop = stepsEl.scrollHeight;
        // 监控面板: 大屏实时输出 + token 累计 (按字符数粗估)
        const monStream = document.getElementById("mon-stream");
        if (monStream) {
            if (monStream.querySelector(".italic")) monStream.textContent = "";
            monStream.textContent += content;
            if (monStream.textContent.length > 4000) {
                monStream.textContent = "..." + monStream.textContent.slice(-3600);
            }
            monStream.scrollTop = monStream.scrollHeight;
        }
        aiopsMonitor.tokenCount += content.length;
        // 真实 usage 还没回来时, 用字符流粗估占位; usage 一到就被覆盖.
        if (!aiopsMonitor.hasRealUsage) {
            setText("mon-tokens", String(aiopsMonitor.tokenCount));
            setText("mon-tokens-detail", `~流字符 ${aiopsMonitor.tokenCount}`);
        }
    } else if (t === "usage") {
        // 后端 tool_runner 在每轮 LLM 末帧 emit, DeepSeek/DashScope 都通过
        // stream_options.include_usage / stream_usage=true 拿到真实 token.
        // 这里把多轮累加, 给 SRE 看真实成本.
        aiopsMonitor.hasRealUsage = true;
        aiopsMonitor.realInputTokens  += d.input_tokens  || 0;
        aiopsMonitor.realOutputTokens += d.output_tokens || 0;
        aiopsMonitor.realTotalTokens  += d.total_tokens  || 0;
        if (d.cache_hit_tokens != null)  aiopsMonitor.cacheHitTokens  += d.cache_hit_tokens;
        if (d.cache_miss_tokens != null) aiopsMonitor.cacheMissTokens += d.cache_miss_tokens;
        setText("mon-tokens", String(aiopsMonitor.realOutputTokens));
        const parts = [
            `输入 ${aiopsMonitor.realInputTokens}`,
            `输出 ${aiopsMonitor.realOutputTokens}`,
        ];
        if (aiopsMonitor.cacheHitTokens > 0 || aiopsMonitor.cacheMissTokens > 0) {
            parts.push(`缓存命中 ${aiopsMonitor.cacheHitTokens}`);
        }
        const detailEl = document.getElementById("mon-tokens-detail");
        if (detailEl) {
            detailEl.textContent = parts.join(" · ");
            detailEl.title = `合计 ${aiopsMonitor.realTotalTokens} tokens` +
                (d.model ? ` · ${d.model}` : "");
        }
        setText("mon-tokens-badge", "API 实测");
    } else if (t === "tool_call") {
        // 监控面板: 工具调用累计 + 流水列表
        aiopsMonitor.toolCount += 1;
        const ok = d.success !== false && d.status !== "failed"; // 后端 ok=true / success=true 都算成功
        if (!ok) aiopsMonitor.toolFail += 1;
        aiopsTrace.addTool(d);
        setText("mon-tools", String(aiopsMonitor.toolCount));
        setText("mon-tools-fail", `失败 ${aiopsMonitor.toolFail}`);
        const feed = document.getElementById("mon-tool-feed");
        if (feed) {
            // 首次清掉占位
            if (feed.querySelector(".italic")) feed.innerHTML = "";
            const row = document.createElement("div");
            const ok = d.success !== false;
            const statusIcon = ok ? "✓" : "✗";
            const elapsed = d.elapsed_ms != null ? `${d.elapsed_ms}ms` : "";
            row.className = "tool-row";
            row.innerHTML = `<span class="${ok ? "tk-ok" : "tk-fail"}">${statusIcon}</span>
                <span class="tk-name">${escapeHtml(d.name || "?")}</span>
                <span class="tk-time">${escapeHtml(elapsed)}</span>`;
            feed.appendChild(row);
            feed.scrollTop = feed.scrollHeight;
        }
    } else if (t === "step_complete") {
        // 把之前 executing 的卡片收紧成 done + 替换为结果预览
        const iter = d.iteration || 0;
        let div = stepsEl.querySelector(`[data-step-iter="${iter}"]`);
        if (!div) {
            div = document.createElement("div");
            div.dataset.stepIter = String(iter);
            stepsEl.appendChild(div);
        }
        div.className = "step-item done";
        div.innerHTML = `<div class="step-title">✓ 步骤 ${escapeHtml(String(iter))}</div>
            <div class="step-desc">${escapeHtml(d.step || "")}</div>
            <div class="step-preview">${escapeHtml((d.result_preview || "").slice(0, 200))}</div>`;
        stepsEl.scrollTop = stepsEl.scrollHeight;
        statusEl.textContent = `已完成 ${d.iteration} 步`;
        {
            const s = aiopsTrace.ensureStep(d.iteration, d.step);
            s.preview = d.result_preview || "";
        }
    } else if (t === "replan") {
        const div = document.createElement("div");
        div.className = "step-item replan-note";
        div.innerHTML = `<div>Replanner 调整: 剩余 ${(d.plan || []).length} 步</div>`;
        stepsEl.appendChild(div);
        stepsEl.scrollTop = stepsEl.scrollHeight;
    } else if (t === "report") {
        showAiopsReport();
        reportEl.innerHTML = renderMarkdown(d.report || "");
        statusEl.textContent = "报告已生成";
        setText("mon-stream-hint", "已完成");
        renderTrace();
    } else if (t === "action_request") {
        showAiopsReport();
        const planText = d.plan || "";
        reportEl.innerHTML += `
            <div class="hitl-block">
                <h3 class="hitl-title">
                    <span class="animate-pulse">⚠</span> 提议的自愈修复方案
                </h3>
                <div class="hitl-plan">${escapeHtml(planText)}</div>
                <div class="hitl-actions">
                    <button onclick="window.resumeAiops(true)" class="btn-approve">✓ 授权并执行修复</button>
                    <button onclick="window.resumeAiops(false)" class="btn-deny">✗ 拒绝执行</button>
                </div>
            </div>
        `;
        statusEl.textContent = "等待人工授权…";
    } else if (t === "complete") {
        statusEl.textContent = "完成 ✓";
    } else if (t === "error") {
        showAiopsReport();
        reportEl.innerHTML = `<p class="text-red-500">错误: ${escapeHtml(ev.message)}</p>`;
        statusEl.textContent = "失败 ✗";
    }
}

async function resumeAiops(approved) {
    if (!currentSessionId) return;

    const reportEl = document.getElementById("aiops-report");
    const statusEl = document.getElementById("aiops-status");

    // Disable buttons
    const btns = reportEl.querySelectorAll("button");
    btns.forEach(b => {
        b.disabled = true;
        b.classList.add("opacity-50", "cursor-not-allowed");
    });

    statusEl.textContent = approved ? "授权通过，执行中..." : "已拒绝修复，结束流程...";
    document.getElementById("aiops-stop").disabled = false;
    aiopsAbortController = new AbortController();

    try {
        const resp = await fetch(`${API}/aiops/diagnose`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: currentSessionId,
                query: "", // Not needed for resume
                resume_action: true,
                action_approved: approved
            }),
            signal: aiopsAbortController.signal,
        });
        await consumeSSE(resp, (ev) => handleAiopsEvent(ev, document.getElementById("aiops-plan"), document.getElementById("aiops-steps"), reportEl, statusEl));
        if (approved) {
            statusEl.textContent = "修复执行完毕 ✓";
        } else {
            statusEl.textContent = "流程已结束 ✓";
        }
    } catch (e) {
        if (e.name === "AbortError") {
            statusEl.textContent = "已停止";
        } else {
            statusEl.textContent = "执行失败 ✗";
            reportEl.innerHTML += `<p class="text-red-500 mt-2">恢复执行失败: ${e.message}</p>`;
        }
    } finally {
        document.getElementById("aiops-stop").disabled = true;
        aiopsAbortController = null;
    }
}
window.resumeAiops = resumeAiops;

// ============================================================
// RAG Chat
// ============================================================
const chatInput = document.getElementById("chat-input");
const chatSend = document.getElementById("chat-send");
const chatWebToggle = document.getElementById("chat-web-toggle");
const chatWebState = document.getElementById("chat-web-state");
const chatMcpToggle = document.getElementById("chat-mcp-toggle");
const chatMcpState = document.getElementById("chat-mcp-state");
let chatWebEnabled = false;
let chatMcpEnabled = true;

function renderChatWebToggle() {
    if (!chatWebToggle) return;
    chatWebToggle.classList.toggle("on", chatWebEnabled);
    chatWebState.textContent = chatWebEnabled ? "开" : "关";
}
if (chatWebToggle) {
    chatWebToggle.addEventListener("click", () => {
        chatWebEnabled = !chatWebEnabled;
        renderChatWebToggle();
    });
    renderChatWebToggle();
}

function renderChatMcpToggle() {
    if (!chatMcpToggle) return;
    chatMcpToggle.classList.toggle("on", chatMcpEnabled);
    chatMcpState.textContent = chatMcpEnabled ? "开" : "关";
}
if (chatMcpToggle) {
    chatMcpToggle.addEventListener("click", () => {
        chatMcpEnabled = !chatMcpEnabled;
        renderChatMcpToggle();
    });
    renderChatMcpToggle();
}

chatSend.addEventListener("click", sendChat);
chatInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendChat();
    }
});

async function sendChat() {
    const question = chatInput.value.trim();
    if (!question) return;
    chatInput.value = "";

    appendChatMsg("user", question);
    const progressBox = appendChatProgress();
    const thinkingBubble = appendThinkingBubble();
    thinkingBubble.wrap.style.display = "none"; // 等有 reasoning 再显
    const assistantBubble = appendChatMsg("assistant", "");
    assistantBubble.parentElement.style.display = "none"; // 等第一个 token 再显
    chatSend.disabled = true;

    try {
        const resp = await fetch(`${API}/chat/stream`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: "web-chat",
                question,
                top_k: 3,
                web_search: chatWebEnabled,
                mcp_tools: chatMcpEnabled,
            }),
        });

        let buf = "";
        let thinkBuf = "";
        let tokenStarted = false;
        let thinkingStarted = false;
        await consumeSSE(resp, (ev) => {
            if (ev.type === "progress") {
                appendChatProgressRow(progressBox, ev);
            } else if (ev.type === "thinking") {
                if (!thinkingStarted) {
                    thinkingStarted = true;
                    thinkingBubble.wrap.style.display = "";
                }
                thinkBuf += ev.content;
                thinkingBubble.content.textContent = thinkBuf;
                const container = document.getElementById("chat-messages");
                container.scrollTop = container.scrollHeight;
            } else if (ev.type === "token") {
                if (!tokenStarted) {
                    tokenStarted = true;
                    finalizeChatProgress(progressBox);
                    // 答案开始时把思考气泡自动折叠 (仍可点开)
                    if (thinkingStarted) collapseThinkingBubble(thinkingBubble);
                    assistantBubble.parentElement.style.display = "";
                }
                buf += ev.content;
                assistantBubble.innerHTML = renderMarkdown(buf);
                const container = document.getElementById("chat-messages");
                container.scrollTop = container.scrollHeight;
            } else if (ev.type === "error") {
                finalizeChatProgress(progressBox, true);
                assistantBubble.parentElement.style.display = "";
                assistantBubble.innerHTML = `<span class="text-red-500">错误: ${escapeHtml(ev.message)}</span>`;
            }
        });
        if (!tokenStarted) {
            // 没拿到任何 token, 清理占位气泡
            assistantBubble.parentElement.remove();
        }
        if (!thinkingStarted) {
            thinkingBubble.wrap.remove();
        }
    } catch (e) {
        finalizeChatProgress(progressBox, true);
        assistantBubble.parentElement.style.display = "";
        assistantBubble.innerHTML = `<span class="text-red-500">网络错误: ${e.message}</span>`;
    } finally {
        chatSend.disabled = false;
        chatInput.focus();
    }
}

// --- RAG Chat 思考过程气泡 (qwen3/qwen-plus-latest 等支持 thinking 的模型才会有) ---
function appendThinkingBubble() {
    const container = document.getElementById("chat-messages");
    const placeholder = container.querySelector(".placeholder.text-center");
    if (placeholder) placeholder.remove();

    const wrap = document.createElement("div");
    wrap.className = "flex justify-start";
    wrap.innerHTML = `
      <div class="rag-thinking">
        <div class="rag-thinking-head">
          <span>🧠</span>
          <span>思考过程</span>
          <span class="rag-thinking-toggle">▼ 收起</span>
        </div>
        <pre class="rag-thinking-content"></pre>
      </div>`;
    container.appendChild(wrap);
    container.scrollTop = container.scrollHeight;

    const box = wrap.querySelector(".rag-thinking");
    const content = wrap.querySelector(".rag-thinking-content");
    const head = wrap.querySelector(".rag-thinking-head");
    const toggle = wrap.querySelector(".rag-thinking-toggle");
    head.addEventListener("click", () => {
        const hidden = content.classList.toggle("hidden");
        toggle.textContent = hidden ? "▶ 展开" : "▼ 收起";
    });
    return { wrap, box, content, head, toggle };
}

function collapseThinkingBubble(bundle) {
    if (!bundle || !bundle.content) return;
    bundle.content.classList.add("hidden");
    if (bundle.toggle) bundle.toggle.textContent = "▶ 展开";
}

// --- RAG Chat 进度条 (类似 AIOps 步骤卡片) ---
function appendChatProgress() {
    const container = document.getElementById("chat-messages");
    const placeholder = container.querySelector(".placeholder.text-center");
    if (placeholder) placeholder.remove();

    const wrap = document.createElement("div");
    wrap.className = "flex justify-start";
    wrap.innerHTML = `
      <div class="rag-progress">
        <div class="rag-progress-head">
          <span class="rag-spinner animate-pulse"></span>
          <span>正在检索并生成回答…</span>
        </div>
        <div class="rag-progress-rows"></div>
      </div>`;
    container.appendChild(wrap);
    container.scrollTop = container.scrollHeight;
    return wrap.querySelector(".rag-progress");
}

function appendChatProgressRow(box, ev) {
    if (!box) return;
    const rows = box.querySelector(".rag-progress-rows");
    const icon = iconForRagStage(ev.stage);
    const elapsed = Number.isFinite(ev.elapsed_ms) && ev.elapsed_ms > 0
        ? `<span class="ml-1 text-[10px] text-indigo-500">${ev.elapsed_ms}ms</span>`
        : "";

    const detailsHtml = renderRagStageDetails(ev.stage, ev.data || {});
    const hasDetails = !!detailsHtml;

    const row = document.createElement("div");
    row.className = "rag-progress-row";

    const headLine = document.createElement("div");
    headLine.className = "flex items-center gap-1.5 flex-wrap" + (hasDetails ? " cursor-pointer rounded px-0.5 -mx-0.5" : "");
    headLine.innerHTML = `
      <span class="shrink-0">${icon}</span>
      <span class="row-label">${escapeHtml(ev.label || ev.stage || "")}</span>
      ${ev.detail ? `<span class="row-detail truncate">${escapeHtml(ev.detail)}</span>` : ""}
      ${elapsed}
      ${hasDetails ? `<span class="rag-toggle">▶ 详情</span>` : ""}`;
    row.appendChild(headLine);

    if (hasDetails) {
        const panel = document.createElement("div");
        panel.className = "rag-details hidden";
        panel.innerHTML = detailsHtml;
        row.appendChild(panel);
        headLine.addEventListener("click", () => {
            const opened = !panel.classList.contains("hidden");
            panel.classList.toggle("hidden");
            const tog = headLine.querySelector(".rag-toggle");
            if (tog) tog.textContent = opened ? "▶ 详情" : "▼ 收起";
        });
    }

    rows.appendChild(row);
    const container = document.getElementById("chat-messages");
    container.scrollTop = container.scrollHeight;
}

function renderRagStageDetails(stage, data) {
    if (!data || typeof data !== "object") return "";
    if (stage === "rewrite_done") {
        const orig = data.original || "";
        const rew = data.rewritten || "";
        if (!orig && !rew) return "";
        return `
          <div><span class="text-slate-400">原始:</span> ${escapeHtml(orig)}</div>
          <div><span class="text-slate-400">改写:</span> ${escapeHtml(rew)}</div>`;
    }
    if (stage === "retrieve_done") {
        const hits = Array.isArray(data.hits) ? data.hits : [];
        if (!hits.length) return `<div class="text-slate-400">无命中片段</div>`;
        const meta = `<div class="text-slate-400 mb-1">top_k=${data.top_k ?? "?"} · ${escapeHtml(data.mode || "")}</div>`;
        const items = hits.map((h, i) => {
            const score = (h.score !== null && h.score !== undefined) ? `<span class="text-emerald-600">score ${h.score}</span>` : "";
            const chap = h.chapter ? ` · 章节: ${escapeHtml(h.chapter)}` : "";
            return `
              <div class="border-l-2 border-indigo-200 pl-2">
                <div class="font-medium text-slate-700">${i + 1}. ${escapeHtml(h.source || "未知")} ${score}${chap}</div>
                <div class="text-slate-500">${escapeHtml(h.preview || "")}</div>
              </div>`;
        }).join("");
        return meta + items;
    }
    if (stage === "web_done") {
        const results = Array.isArray(data.results) ? data.results : [];
        if (!results.length) {
            const reason = data.skip_reason || "未触发联网";
            return `<div class="text-slate-400">${escapeHtml(reason)}</div>`;
        }
        const meta = data.provider ? `<div class="text-slate-400 mb-1">provider=${escapeHtml(data.provider)}</div>` : "";
        const items = results.map((r, i) => {
            const url = r.url || "";
            const titleEsc = escapeHtml(r.title || "(无标题)");
            const titleHtml = url
                ? `<a href="${escapeHtml(url)}" target="_blank" rel="noopener" class="text-indigo-600 hover:underline">${titleEsc}</a>`
                : titleEsc;
            return `
              <div class="border-l-2 border-emerald-200 pl-2">
                <div class="font-medium">${i + 1}. ${titleHtml}</div>
                ${url ? `<div class="text-[10px] text-slate-400 break-all">${escapeHtml(url)}</div>` : ""}
                <div class="text-slate-500">${escapeHtml(r.snippet || "")}</div>
              </div>`;
        }).join("");
        return meta + items;
    }
    if (stage === "stats") {
        return `
          <div>模型: <span class="font-medium">${escapeHtml(data.model || "?")}</span></div>
          <div>输入 tokens: <span class="font-medium">${data.input_tokens ?? 0}</span></div>
          <div>输出 tokens: <span class="font-medium">${data.output_tokens ?? 0}</span></div>
          <div>合计 tokens: <span class="font-medium">${data.total_tokens ?? 0}</span></div>
          <div>生成耗时: <span class="font-medium">${data.llm_ms ?? 0} ms</span></div>
          <div>总耗时: <span class="font-medium">${data.total_ms ?? 0} ms</span></div>
          <div>回答字数: <span class="font-medium">${data.answer_chars ?? 0}</span></div>
          ${data.tools_enabled ? '<div class="text-emerald-600">工具回合: 已启用</div>' : ''}`;
    }
    if (stage === "llm_start") {
        const tools = Array.isArray(data.tools) ? data.tools : [];
        if (data.tools_enabled && tools.length) {
            const chips = tools.map(name => `<span class="inline-block px-1.5 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-100 mr-1 mb-1 font-mono text-[10px]">${escapeHtml(name)}</span>`).join("");
            return `
              <div class="text-slate-500 mb-1">模型: <span class="font-medium">${escapeHtml(data.model || "?")}</span></div>
              <div class="text-slate-500 mb-1">已为模型启用 ${tools.length} 个只读工具, 模型可按需自主调用:</div>
              <div class="flex flex-wrap">${chips}</div>`;
        }
        return `<div class="text-slate-500">模型: <span class="font-medium">${escapeHtml(data.model || "?")}</span> · 工具回合: 未启用</div>`;
    }
    if (stage === "tool_call") {
        const ok = (data.status || "").toLowerCase() === "ok";
        const statusColor = ok ? "text-emerald-600" : "text-rose-600";
        const statusIcon = ok ? "✓" : "✗";
        return `
          <div>工具: <span class="font-mono text-slate-700">${escapeHtml(data.name || "?")}</span></div>
          <div>状态: <span class="${statusColor} font-medium">${statusIcon} ${escapeHtml(data.status || "?")}</span></div>
          <div>耗时: <span class="font-medium">${data.elapsed_ms ?? 0} ms</span></div>
          <div>输出: <span class="font-medium">${data.result_chars ?? 0} 字符</span></div>
          ${data.read_only === false ? '<div class="text-amber-600">⚠ 非只读工具</div>' : ''}`;
    }
    return "";
}

function finalizeChatProgress(box, failed = false) {
    if (!box) return;
    const head = box.querySelector(".rag-progress-head");
    if (head) {
        head.innerHTML = failed
            ? `<span class="text-red-500">✗ 检索流程中断</span>`
            : `<span class="text-emerald-600">✓ 检索流程完成</span>`;
    }
}

function iconForRagStage(stage) {
    switch (stage) {
        case "rewrite":      return "✏️";
        case "rewrite_done": return "✅";
        case "retrieve":     return "🔍";
        case "retrieve_done":return "📚";
        case "web":          return "🌐";
        case "web_done":     return "🌐";
        case "llm_start":    return "🤖";
        case "tool_call":    return "🛠️";
        case "stats":        return "📊";
        default:             return "•";
    }
}

function appendChatMsg(role, content) {
    const container = document.getElementById("chat-messages");
    // 清掉初始提示
    const placeholder = container.querySelector(".placeholder.text-center");
    if (placeholder) placeholder.remove();

    const wrap = document.createElement("div");
    wrap.className = "flex " + (role === "user" ? "justify-end" : "justify-start");
    const bubble = document.createElement("div");
    bubble.className = `chat-msg ${role}`;
    bubble.innerHTML = role === "user" ? escapeHtml(content) : renderMarkdown(content);
    wrap.appendChild(bubble);
    container.appendChild(wrap);
    container.scrollTop = container.scrollHeight;
    return bubble;
}

// ============================================================
// 文档管理
// ============================================================
const uploadZone = document.getElementById("upload-zone");
const uploadInput = document.getElementById("upload-input");
const uploadResult = document.getElementById("upload-result");
const KB_ADMIN_TOKEN_KEY = "multi_agent_kb_admin_token";

uploadZone.addEventListener("click", () => uploadInput.click());
uploadInput.addEventListener("change", () => uploadInput.files[0] && uploadFile(uploadInput.files[0]));
uploadZone.addEventListener("dragover", (e) => { e.preventDefault(); uploadZone.classList.add("bg-indigo-50"); });
uploadZone.addEventListener("dragleave", () => uploadZone.classList.remove("bg-indigo-50"));
uploadZone.addEventListener("drop", (e) => {
    e.preventDefault();
    uploadZone.classList.remove("bg-indigo-50");
    if (e.dataTransfer.files[0]) uploadFile(e.dataTransfer.files[0]);
});
document.getElementById("docs-refresh").addEventListener("click", loadDocs);

async function uploadFile(file) {
    uploadResult.innerHTML = `<div class="text-indigo-600">⏳ 上传 ${escapeHtml(file.name)} ...</div>`;
    const formData = new FormData();
    formData.append("file", file);
    try {
        const r = await fetch(`${API}/documents/upload`, {
            method: "POST",
            headers: { "X-KB-Admin-Token": getKbAdminToken() },
            body: formData,
        });
        const data = await r.json().catch(() => null);
        if (!r.ok) {
            if (r.status === 401 || r.status === 403) sessionStorage.removeItem(KB_ADMIN_TOKEN_KEY);
            throw new Error(data?.detail || data?.message || `HTTP ${r.status}`);
        }
        if (data.code === "SUCCESS") {
            uploadResult.innerHTML = `<div class="text-emerald-600">✓ 已索引 ${data.data.chunks_indexed} 个 chunk (${data.data.bytes} bytes)</div>`;
            loadDocs();
        } else {
            uploadResult.innerHTML = `<div class="text-red-500">✗ ${escapeHtml(data?.message || "上传失败")}</div>`;
        }
    } catch (e) {
        uploadResult.innerHTML = `<div class="text-red-500">✗ ${escapeHtml(e.message)}</div>`;
    }
}

async function loadDocs() {
    const listEl = document.getElementById("docs-list");
    listEl.innerHTML = '<span class="placeholder">加载中…</span>';
    try {
        const r = await fetch(`${API}/documents`);
        const data = await r.json();
        const docs = data?.data?.documents || [];
        if (docs.length === 0) {
            listEl.innerHTML = '<span class="placeholder">暂无文档, 请先上传</span>';
            return;
        }
        listEl.innerHTML = "";
        docs.forEach((d) => {
            const div = document.createElement("div");
            div.className = "doc-card";
            div.innerHTML = `
                <div>
                    <div class="doc-name">${escapeHtml(d.source)}</div>
                    <div class="doc-meta">${d.chunk_count} 个 chunk</div>
                </div>
                <button class="doc-del" data-source="${escapeHtml(d.source)}">删除</button>
            `;
            div.querySelector("button").addEventListener("click", (e) => {
                if (confirm(`确认删除 ${d.source}?`)) deleteDoc(d.source);
            });
            listEl.appendChild(div);
        });
    } catch (e) {
        listEl.innerHTML = `<span class="text-red-500">加载失败: ${e.message}</span>`;
    }
}

async function deleteDoc(source) {
    try {
        const r = await fetch(`${API}/documents/${encodeURIComponent(source)}`, {
            method: "DELETE",
            headers: { "X-KB-Admin-Token": getKbAdminToken() },
        });
        const data = await r.json().catch(() => null);
        if (!r.ok || data?.code !== "SUCCESS") {
            if (r.status === 401 || r.status === 403) sessionStorage.removeItem(KB_ADMIN_TOKEN_KEY);
            throw new Error(data?.detail || data?.message || `HTTP ${r.status}`);
        }
        loadDocs();
    } catch (e) {
        alert(`删除失败: ${e.message}`);
    }
}

function getKbAdminToken() {
    let token = sessionStorage.getItem(KB_ADMIN_TOKEN_KEY) || "";
    if (!token) {
        token = prompt("请输入知识库管理员 Token") || "";
        token = token.trim();
        if (!token) throw new Error("未输入管理员 Token");
        sessionStorage.setItem(KB_ADMIN_TOKEN_KEY, token);
    }
    return token;
}

// ============================================================
// 工具函数
// ============================================================
async function consumeSSE(response, onEvent) {
    if (!response.ok) {
        const text = await response.text().catch(() => "");
        throw new Error(`HTTP ${response.status}: ${text.slice(0, 200)}`);
    }
    if (!response.body) {
        throw new Error("浏览器不支持 ReadableStream");
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let buffer = "";

    // SSE 标准支持 \r\n / \n / \r 三种分隔, 这里全兼容
    const blockSplit = /\r?\n\r?\n|\n\n/;
    const lineSplit = /\r?\n/;

    while (true) {
        const { done, value } = await reader.read();
        if (done) {
            // 处理最后剩下的 buffer
            if (buffer.trim()) parseBlock(buffer);
            break;
        }
        buffer += decoder.decode(value, { stream: true });

        // 切出所有完整的 event block
        let parts = buffer.split(blockSplit);
        buffer = parts.pop();  // 最后一段可能不完整, 留到下次
        for (const block of parts) parseBlock(block);
    }

    function parseBlock(block) {
        for (const line of block.split(lineSplit)) {
            if (line.startsWith("data:")) {
                const payload = line.slice(5).trim();
                if (!payload) continue;
                try {
                    onEvent(JSON.parse(payload));
                } catch (e) {
                    console.warn("[SSE] JSON parse error:", payload, e);
                }
            }
        }
    }
}

function escapeHtml(s) {
    if (s == null) return "";
    return String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

// ---- Markdown 表格 (容错解析: 兼容真实 LLM 输出缺首尾管道等情况) ----

// 拆一行表格: 去掉首尾 | 后按 | 切分, 并剥掉两端空单元格 (中间的空单元格保留占位)
function splitTableRow(line) {
    let s = line.trim();
    if (s.startsWith("|")) s = s.slice(1);
    if (s.endsWith("|")) s = s.slice(0, -1);
    const cells = s.split("|").map((c) => c.trim());
    while (cells.length && cells[0] === "") cells.shift();
    while (cells.length && cells[cells.length - 1] === "") cells.pop();
    return cells;
}

// 分隔行: 只含 | - : 空白, 且至少有一个 --- 段
function isTableSeparator(line) {
    if (!/^[\s|:-]*$/.test(line) || !line.includes("-")) return false;
    return splitTableRow(line).some((c) => /^:?-+:?$/.test(c));
}

// 表头/数据行: 以 | 开头或行内含 | (容忍缺首尾管道)
function isTableRowLine(line) {
    return line.includes("|");
}

// 一个表格块 → HTML; bodyLines 里的分隔行会被消费掉并解析出列对齐 (:--- 左 / :---: 中 / ---: 右)
function mdTableToHtml(headerLine, bodyLines) {
    const aligns = [];
    const rows = [];
    for (const line of bodyLines) {
        if (isTableSeparator(line)) {
            splitTableRow(line).forEach((c, i) => {
                const l = c.startsWith(":"), r = c.endsWith(":");
                aligns[i] = l && r ? "center" : r ? "right" : "left";
            });
            continue;
        }
        rows.push(splitTableRow(line));
    }
    const ths = splitTableRow(headerLine);
    const alignAttr = (i) =>
        aligns[i] && aligns[i] !== "left" ? ` style="text-align: ${aligns[i]}"` : "";
    const thead = `<thead><tr>${ths.map((t, i) => `<th${alignAttr(i)}>${t}</th>`).join("")}</tr></thead>`;
    const tbody = `<tbody>${rows
        .map((r) => `<tr>${ths.map((_, i) => `<td${alignAttr(i)}>${r[i] ?? ""}</td>`).join("")}</tr>`)
        .join("")}</tbody>`;
    return `<div class="md-table-wrap"><table>${thead}${tbody}</table></div>`;
}

// 逐行扫描, 把表格块 (表头 + 分隔行 + 连续数据行) 替换为 HTML 表格, 其余行原样返回
function scanMarkdownTables(text) {
    const lines = text.split("\n");
    const out = [];
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (isTableRowLine(line) && i + 1 < lines.length && isTableSeparator(lines[i + 1])) {
            const body = [lines[i + 1]];   // 分隔行一并传入, 供解析列对齐
            let j = i + 2;
            while (j < lines.length && isTableRowLine(lines[j])) { body.push(lines[j]); j++; }
            out.push(mdTableToHtml(line, body));
            i = j - 1;
        } else {
            out.push(line);
        }
    }
    return out.join("\n");
}

// 极简 Markdown -> HTML (够用即可, 不引第三方库)
// v3: 表格抽为独立函数 + 容错解析 (缺首尾管道 / 列对齐)
function renderMarkdown(md) {
    if (!md) return "";
    let s = String(md).replace(/\\n/g, "\n").replace(/\\t/g, "\t");
    let h = escapeHtml(s);

    // 表格: 在已转义文本上做结构化转换, 之后的粗体/行内码替换会继续作用在生成的 html 上
    h = scanMarkdownTables(h);

    // 代码块
    h = h.replace(/```([\s\S]*?)```/g, (_, code) => `<pre><code>${code}</code></pre>`);
    // 行内代码
    h = h.replace(/`([^`\n]+)`/g, "<code>$1</code>");
    // 标题
    h = h.replace(/^### (.+)$/gm, "<h3>$1</h3>");
    h = h.replace(/^## (.+)$/gm, "<h2>$1</h2>");
    h = h.replace(/^# (.+)$/gm, "<h1>$1</h1>");
    // 引用块 (SOP 提示等)
    h = h.replace(/^&gt; (.+)$/gm, '<blockquote>$1</blockquote>');
    // 加粗
    h = h.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    // 列表
    h = h.replace(/^[\-\*] (.+)$/gm, "<li>$1</li>");
    h = h.replace(/(<li>[\s\S]*?<\/li>)(\n<li>)/g, "$1$2");
    h = h.replace(/(<li>[\s\S]+?<\/li>)/g, (m) => `<ul>${m}</ul>`);
    h = h.replace(/<\/ul>\s*<ul>/g, "");
    // 段落
    h = h.replace(/\n\n/g, "</p><p>");
    h = h.replace(/\n/g, "<br>");
    // 表格包裹层内的 <br> 还原 (表格已结构化)
    h = h.replace(/(<div class="md-table-wrap">[\s\S]*?<\/div>)/g, (m) => m.replace(/<br>/g, ""));
    return `<p>${h}</p>`;
}
