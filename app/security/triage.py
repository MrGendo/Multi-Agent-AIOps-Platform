"""安全域 Triage 节点: 告警初筛 + 结构化分类.

借鉴 OpenTriage 的 skip 纪律: 明显误报 (扫描器噪声/健康检查触发 IDS) 直接
拦截出 benign 报告, 不烧后续 Scout/Enrich/Analyst 的 token — 这是
「诚实止损」纪律在安全域的对应物.

失败语义与域分类器相反: 这里 fail-严 不 fail-open — LLM 挂了宁可多调查
(should_investigate=True), 不能把真实攻击当噪声放过.
"""

from __future__ import annotations

from loguru import logger

from app.core.llm import get_chat_llm
from app.core.structured import ainvoke_structured
from app.runtime.agent_harness import get_agent_harness
from app.security.state import (
    SEVERITY_MEDIUM,
    VERDICT_BENIGN,
    TriageDecision,
    SecOpsState,
)

# 白名单: LLM 输出非法值时归一
_VALID_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_VALID_ALERT_TYPES = (
    "brute_force",
    "malware",
    "network_scan",
    "data_exfiltration",
    "privilege_escalation",
    "phishing",
    "web_attack",
    "anomaly",
    "unknown",
)


# ============================================================
# 白名单归一
# ============================================================
def _normalize_severity(raw: str) -> str:
    severity = (raw or "").strip().upper()
    return severity if severity in _VALID_SEVERITIES else SEVERITY_MEDIUM


def _normalize_alert_type(raw: str) -> str:
    alert_type = (raw or "").strip().lower().replace("-", "_").replace(" ", "_")
    return alert_type if alert_type in _VALID_ALERT_TYPES else "unknown"


# ============================================================
# skip 路径的初筛报告 (不烧后续 token, 直接在这里出 benign 报告)
# ============================================================
def _build_skip_fact_sheet(alert_text: str, reason: str, alert_type: str, severity: str) -> str:
    indicators_line = "无"
    return (
        "# 安全告警研判报告（初筛拦截）\n\n"
        f"## 告警原文\n\n```\n{(alert_text or '').strip() or '(空)'}\n```\n\n"
        f"## 初判结论\n\n"
        f"- **告警类型**: {alert_type}\n"
        f"- **初判严重度**: {severity}\n"
        f"- **判定**: benign (初筛判定为误报/噪声, 未进入深度调查)\n"
        f"- **初判理由**: {reason or 'Triage 判定该告警为已知噪声模式, 无需继续调查'}\n"
        f"- **关键指标**: {indicators_line}\n\n"
        f"## 建议观察\n\n"
        f"- 该告警已被初筛拦截, 未消耗深度调查资源\n"
        f"- 建议保持常规监控, 如同类告警频率激增或伴随其他异常再升级处理\n"
        f"- 响应模式: observe (仅观察, 无需处置动作)\n"
    )


def _build_triage_messages(alert_text: str) -> list[dict[str, str]]:
    system = (
        "你是安全告警 Triage 分析师, 对告警做结构化初筛, 只输出 json.\n"
        "分类目标:\n"
        "- alert_type: brute_force | malware | network_scan | data_exfiltration | "
        "privilege_escalation | phishing | web_attack | anomaly | unknown\n"
        "- severity: LOW | MEDIUM | HIGH | CRITICAL\n"
        "- key_indicators: 告警中的关键指标 (源 IP/目标资产/账号/行为特征)\n"
        "- should_investigate: 是否值得继续深度调查. 以下情况设 false — "
        "扫描器/监控探针对已知服务的端口探测、健康检查触发 IDS、已知白名单"
        "进程行为、明显重复的已处置告警. 其余一律 true (宁严勿漏)\n"
        "- reason: 一句话初判理由"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": f"安全告警原文:\n{(alert_text or '').strip() or '(空)'}"},
    ]


async def triage_node(state: SecOpsState) -> dict:
    """安全域入口节点: 结构化初筛, 决定 investigate / skip.

    Returns:
        - investigate: 展开写入 alert_type/severity/key_indicators + triage_*,
          verdict/fact_sheet 留给后续节点 (Analyst/Reporter) 产出
        - skip: 直接填 verdict='benign', response_mode='observe', fact_sheet
          (初筛拦截报告), 后续节点可据此短路
        - LLM 失败: fail-严兜底 should_investigate=True 继续调查
    """
    alert_text = state.get("input", "")

    try:
        harness = get_agent_harness()
        router_model = harness.router_model()
        llm = get_chat_llm(model=router_model, temperature=0, timeout=30, max_retries=1)
        decision: TriageDecision = await ainvoke_structured(
            llm=llm,
            schema_cls=TriageDecision,
            messages=_build_triage_messages(alert_text),
            model_name=router_model,
        )
    except Exception as e:
        # fail-严 不 fail-open: LLM 挂了继续调查, 不能漏掉真实攻击
        detail = f"{type(e).__name__}: {e}"
        logger.exception(f"[Triage] LLM 初筛失败, 宁严勿漏继续调查: {e}")
        return {
            "alert_type": "unknown",
            "severity": SEVERITY_MEDIUM,
            "key_indicators": [],
            "should_investigate": True,
            "triage_verdict": "investigate",
            "triage_reason": "Triage LLM 失败，宁严勿漏继续调查",
            "error": f"triage_llm_failed: {detail}",
        }

    alert_type = _normalize_alert_type(decision.alert_type)
    severity = _normalize_severity(decision.severity)
    reason = decision.reason or "Triage 未给出理由"

    logger.info(
        f"[Triage] type={alert_type} severity={severity} "
        f"investigate={decision.should_investigate} | {reason[:120]}"
    )

    if not decision.should_investigate:
        # skip 路径: 直接出 benign 初筛报告, 不烧后续 token
        return {
            "alert_type": alert_type,
            "severity": severity,
            "key_indicators": list(decision.key_indicators or []),
            "should_investigate": False,
            "triage_verdict": "skip",
            "triage_reason": reason,
            "verdict": VERDICT_BENIGN,
            "response_mode": "observe",
            "fact_sheet": _build_skip_fact_sheet(alert_text, reason, alert_type, severity),
        }

    return {
        "alert_type": alert_type,
        "severity": severity,
        "key_indicators": list(decision.key_indicators or []),
        "should_investigate": True,
        "triage_verdict": "investigate",
        "triage_reason": reason,
    }
