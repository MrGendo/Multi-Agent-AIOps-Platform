"""安全域 Reporter 节点: 生成最终研判报告 (FactSheet).

职责边界: Reporter 只组织报告, **不得推翻** Analyst 的 verdict/severity —
报告里的判定字段以 Analyst 产出为准 (单一事实来源, 防止报告层翻案).

响应分级是硬规则 (不依赖 LLM): severity → response_mode 的映射写死在代码里,
LLM 只负责把处置建议组织成 ResponseRecommendation 列表.
"""

from __future__ import annotations

from loguru import logger

from app.core.llm import get_chat_llm
from app.core.structured import ainvoke_structured
from app.runtime.agent_harness import get_agent_harness
from app.security.state import (
    RESPONSE_MODES,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    FactSheet,
    ResponseRecommendation,
    SecOpsState,
)

# severity → response_mode 硬规则映射 (不依赖 LLM)
_SEVERITY_TO_MODE = {
    SEVERITY_LOW: "observe",
    SEVERITY_MEDIUM: "recommend",
    SEVERITY_HIGH: "human_approval",
    SEVERITY_CRITICAL: "human_approval",
}

# 映射表与 RESPONSE_MODES 对齐的模块级断言 (导入期即发现拼写错)
assert set(_SEVERITY_TO_MODE.values()) <= set(RESPONSE_MODES)

# 报告头部固定免责声明 (安全铁律: 研判只产建议, 高风险动作需人工审批)
REPORT_DISCLAIMER = "⚠ 本报告仅为处置建议，高风险动作需人工审批后执行"

_VALID_SEVERITIES = (SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL)


def resolve_response_mode(severity: str) -> str:
    """响应分级硬规则: severity → response_mode (非法 severity 走最严档).

    LOW → observe; MEDIUM → recommend; HIGH/CRITICAL → human_approval.
    """
    return _SEVERITY_TO_MODE.get((severity or "").strip().upper(), "human_approval")


def _normalize_severity(raw: str, fallback: str) -> str:
    severity = (raw or "").strip().upper()
    return severity if severity in _VALID_SEVERITIES else fallback


def _build_reporter_messages(state: SecOpsState) -> list[dict[str, str]]:
    """构造报告 prompt: verdict/severity 以 Analyst 产出为准 (只组织不推翻)."""
    iocs = state.get("iocs") or {}
    iocs_text = "\n".join(
        f"- {kind}: {', '.join(values) if isinstance(values, (list, tuple)) else values}"
        for kind, values in iocs.items()
        if values
    ) or "（未提取到 IOC）"

    intel_text = "\n".join(f"- {snip}" for snip in (state.get("intel_snippets") or [])) or "（无）"

    system = (
        "你是安全研判报告撰写员 (SecOps Reporter). 把 Analyst 的研判整理成一份可执行的"
        "研判报告 (FactSheet), 只输出 json.\n"
        "铁律:\n"
        "1. verdict 与 severity 必须原样使用下面给定的 Analyst 产出, 不得推翻、不得改写 — "
        "你只负责组织报告, 不负责重新研判.\n"
        "2. 每条结论必须能对应到证据: evidence_refs 引用真实存在的 IOC/情报/异常模式.\n"
        "3. attacker_entities 从 IOC 中的可疑来源 (恶意 IP/域名/账号) 选, "
        "victim_entities 从受影响资产选; 拿不准的实体不要编.\n"
        f"4. response_actions 按响应分级给建议: 当前 response_mode={resolve_response_mode(state.get('severity', ''))} "
        "(observe=仅观察建议, recommend=建议动作, human_approval=高风险动作需人工审批).\n"
        "5. 只给建议, 不要虚构已执行的处置."
    )

    user = (
        f"# 告警原文\n{(state.get('input') or '').strip() or '(空)'}\n\n"
        f"# Analyst 研判 (以此为准, 不得推翻)\n"
        f"- verdict: {state.get('verdict') or 'inconclusive'}\n"
        f"- severity: {state.get('severity') or SEVERITY_MEDIUM}\n"
        f"- confidence: {state.get('confidence', 0.0)}\n"
        f"- 评估: {state.get('assessment') or '(无)'}\n"
        f"- 判定依据: {state.get('verdict_reason') or '(无)'}\n\n"
        f"# 提取的 IOC\n{iocs_text}\n\n"
        f"# 外部情报片段\n{intel_text}\n\n"
        f"# MITRE 技术\n{', '.join(state.get('mitre_techniques') or []) or '（无）'}\n\n"
        f"# 异常评分\n{state.get('anomaly_score', 0.0)} — {state.get('anomaly_reason') or '无描述'}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def _classify_entities(iocs: dict) -> tuple[list[str], list[str]]:
    """从 IOC dict 里分攻击者/受害者实体.

    尝试用 classify_ips 的结果 (iocs['ip_classification'] 等); 若 Scout 未写入
    分类结果, 则退化为启发式: 来源侧 (src_/attacker) 视为攻击者, 其余可疑
    IP/域名归攻击者, 受影响资产信息不足时留空.
    """
    attackers: list[str] = []
    victims: list[str] = []
    seen: set[str] = set()

    def _add(bucket: list[str], value: str) -> None:
        v = (value or "").strip()
        if v and v not in seen:
            seen.add(v)
            bucket.append(v)

    classification = iocs.get("ip_classification") or iocs.get("classified_ips") or {}
    if isinstance(classification, dict):
        for ip, label in classification.items():
            label_str = str(label or "").lower()
            if any(k in label_str for k in ("malicious", "suspicious", "attacker", "src", "source", "external")):
                _add(attackers, ip)
            elif any(k in label_str for k in ("victim", "internal", "dst", "target", "benign")):
                _add(victims, ip)

    for key in ("attacker_ips", "src_ips", "suspicious_ips", "malicious_ips"):
        for item in iocs.get(key) or []:
            _add(attackers, item if isinstance(item, str) else str(item))
    for key in ("victim_ips", "dst_ips", "target_assets", "victim_assets"):
        for item in iocs.get(key) or []:
            _add(victims, item if isinstance(item, str) else str(item))

    for domain in iocs.get("domains") or []:
        _add(attackers, domain)
    for user in (iocs.get("attacker_accounts") or iocs.get("accounts") or []):
        _add(attackers, user)

    return attackers, victims


def _fallback_actions(response_mode: str) -> list[ResponseRecommendation]:
    """规则模板的处置建议占位 (LLM 失败时)."""
    if response_mode == "observe":
        actions = [
            ("持续观察该来源的后续告警，暂不处置", "低severity，仅观察即可"),
            ("如同类告警频率激增再升级处理", "避免过度反应"),
        ]
    elif response_mode == "recommend":
        actions = [
            ("核查告警涉及资产的近期登录与进程记录", "确认是否有实际失陷"),
            ("将可疑来源 IP 加入监控名单（仅监控，不封禁）", "中等级别，建议先核查再动作"),
            ("保留现场日志供后续溯源", "证据留存"),
        ]
    else:
        actions = [
            ("隔离受影响资产（需人工审批）", "高风险动作，防止横向移动"),
            ("封禁攻击来源 IP（需人工审批）", "阻断在野攻击"),
            ("重置可能泄露的凭据（需人工审批）", "防凭据滥用"),
            ("上报安全应急响应组", "HIGH/CRITICAL 需要人工介入"),
        ]
    return [
        ResponseRecommendation(action=a, rationale=r, requires_approval=response_mode == "human_approval")
        for a, r in actions
    ]


def _render_fallback_fact_sheet(state: SecOpsState, verdict: str, severity: str,
                                response_mode: str) -> str:
    """LLM 失败时的规则模板 Markdown 报告 (不拍平换行, 不中断)."""
    iocs = state.get("iocs") or {}
    ioc_lines = []
    for kind, values in iocs.items():
        if not values:
            continue
        if isinstance(values, (list, tuple)):
            for v in values:
                ioc_lines.append(f"| {kind} | {v} |")
        else:
            ioc_lines.append(f"| {kind} | {values} |")
    ioc_table = "\n".join(ioc_lines) if ioc_lines else "| (无) | (无) |"

    actions = _fallback_actions(response_mode)
    action_lines = "\n".join(
        f"- [{i}] {a.action}（{a.rationale}）" + (" — 需人工审批" if a.requires_approval else "")
        for i, a in enumerate(actions, 1)
    )

    return (
        f"# 安全告警研判报告（规则模板）\n\n"
        f"{REPORT_DISCLAIMER}\n\n"
        f"## 判定结论\n\n"
        f"- **Verdict**: {verdict}\n"
        f"- **Severity**: {severity}\n"
        f"- **响应模式**: {response_mode}\n"
        f"- **置信度**: {state.get('confidence', 0.0)}\n\n"
        f"## 告警概况\n\n"
        f"- **告警类型**: {state.get('alert_type') or 'unknown'}\n"
        f"- **异常评分**: {state.get('anomaly_score', 0.0)} — {state.get('anomaly_reason') or '无描述'}\n"
        f"- **研判摘要**: {state.get('assessment') or '（研判 LLM 失败，无评估文本）'}\n\n"
        f"## IOC 列表\n\n"
        f"| 类型 | 值 |\n|---|---|\n{ioc_table}\n\n"
        f"## MITRE ATT&CK\n\n"
        f"{', '.join(state.get('mitre_techniques') or []) or '（无）'}\n\n"
        f"## 处置建议（占位，需人工确认）\n\n"
        f"{action_lines}\n"
    )


def _render_fact_sheet(sheet: FactSheet, response_mode: str) -> str:
    """把 FactSheet schema 渲染成 Markdown (response_mode 用硬规则值覆盖)."""
    mitre = ", ".join(sheet.mitre_techniques) or "（无）"
    attackers = ", ".join(sheet.attacker_entities) or "（未知）"
    victims = ", ".join(sheet.victim_entities) or "（未知）"

    action_lines = "\n".join(
        f"- [{i}] {a.action}"
        + (f" — {a.rationale}" if a.rationale else "")
        + (" — 需人工审批" if a.requires_approval else "")
        for i, a in enumerate(sheet.response_actions, 1)
    ) or "（无）"

    return (
        f"# 安全告警研判报告\n\n"
        f"{REPORT_DISCLAIMER}\n\n"
        f"## 执行摘要\n\n"
        f"{sheet.summary}\n\n"
        f"## 判定结论\n\n"
        f"- **Verdict**: {sheet.verdict}\n"
        f"- **Severity**: {sheet.severity}\n"
        f"- **响应模式**: {response_mode}\n\n"
        f"## 实体\n\n"
        f"- **攻击者**: {attackers}\n"
        f"- **受害者**: {victims}\n\n"
        f"## MITRE ATT&CK\n\n"
        f"{mitre}\n\n"
        f"## 证据引用\n\n"
        + ("\n".join(f"- {r}" for r in sheet.evidence_refs) or "（无）")
        + "\n\n"
        f"## 处置建议\n\n"
        f"{action_lines}\n"
    )


async def reporter_node(state: SecOpsState) -> dict:
    """生成最终研判报告.

    Returns: {'fact_sheet', 'verdict', 'severity', 'response_mode', 'response_actions'}
      - verdict/severity 以 Analyst 产出为准 (Reporter 不得推翻)
      - response_mode 由 severity 硬规则决定 (不依赖 LLM)
      - response_actions 转成 'action — rationale' 字符串列表
      - LLM 失败: 规则模板兑底, 不中断
    """
    verdict = state.get("verdict") or "inconclusive"
    severity = _normalize_severity(state.get("severity", ""), "MEDIUM")
    response_mode = resolve_response_mode(severity)

    try:
        harness = get_agent_harness()
        model = harness.report_model()
        llm = get_chat_llm(model=model, temperature=0.2, timeout=60, max_retries=1)
        sheet: FactSheet = await ainvoke_structured(
            llm=llm,
            schema_cls=FactSheet,
            messages=_build_reporter_messages(state),
            model_name=model,
        )
    except Exception as e:
        detail = f"{type(e).__name__}: {e}"
        logger.warning(f"[Reporter] 报告 LLM 失败, 使用规则模板兑底: {e}")
        actions = _fallback_actions(response_mode)
        fact_sheet = _render_fallback_fact_sheet(state, verdict, severity, response_mode)
        return {
            "fact_sheet": fact_sheet,
            "verdict": verdict,
            "severity": severity,
            "response_mode": response_mode,
            "response_actions": [_format_action(a) for a in actions],
            "error": f"reporter_llm_failed: {detail}",
        }

    # Reporter 不得推翻: LLM 输出的 verdict/severity 一律以 Analyst 产出覆盖
    final_verdict = verdict
    final_severity = _normalize_severity(severity, sheet.severity or "MEDIUM")

    # requires_approval 硬规则: human_approval 档全 true, 其余保持 schema 安全默认 (true)
    actions = []
    for a in sheet.response_actions or []:
        requires = True if response_mode == "human_approval" else bool(a.requires_approval)
        actions.append(
            ResponseRecommendation(
                action=a.action,
                rationale=a.rationale,
                requires_approval=requires,
            )
        )
    if not actions:
        actions = _fallback_actions(response_mode)

    # 实体缺失时用 classify_ips 结果补齐
    attackers, victims = _classify_entities(state.get("iocs") or {})
    if not sheet.attacker_entities and attackers:
        sheet = sheet.model_copy(update={"attacker_entities": attackers})
    if not sheet.victim_entities and victims:
        sheet = sheet.model_copy(update={"victim_entities": victims})

    fact_sheet = _render_fact_sheet(sheet, response_mode)
    logger.info(
        f"[Reporter] 报告完成 verdict={final_verdict} severity={final_severity} mode={response_mode}"
    )

    return {
        "fact_sheet": fact_sheet,
        "verdict": final_verdict,
        "severity": final_severity,
        "response_mode": response_mode,
        "response_actions": [_format_action(a) for a in actions],
    }


def _format_action(action: ResponseRecommendation) -> str:
    """处置动作转 'action — rationale' 字符串."""
    if action.rationale:
        return f"{action.action} — {action.rationale}"
    return action.action
