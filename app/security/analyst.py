"""安全域 Analyst 节点: 威胁研判核心.

读取 Scout 产出的 iocs/anomaly_score/intel_snippets/mitre_techniques,
调 LLM (AnalystAssessment schema, router 模型) 输出:
威胁评估 + 置信度 + verdict 四态判定.

证据纪律 (借鉴 OpenTriage 反幻觉纪律):
  - 结论必须引用证据 (哪条 IOC / 哪条情报支撑)
  - 外部威胁情报仅供参考, 不直接定罪
  - 置信度 < CONFIDENCE_THRESHOLD 时 needs_more_data=true, 由 graph 路由
    决定是否回环 Scout 补充证据 (analyst 只写临时字段, 不做路由决策)
"""

from __future__ import annotations

from loguru import logger

from app.core.llm import get_chat_llm
from app.core.structured import ainvoke_structured
from app.runtime.agent_harness import get_agent_harness
from app.security.state import (
    CONFIDENCE_THRESHOLD,
    VERDICT_INCONCLUSIVE,
    AnalystAssessment,
    SecOpsState,
)

# verdict 四态白名单 (LLM 输出非法值时归一到 inconclusive)
_VALID_VERDICTS = ("benign", "suspicious", "malicious", "inconclusive")

# LLM 失败兑底时置信度封顶: fail-soft 可以保守但不能盲目自信
_FALLBACK_CONFIDENCE_CAP = 0.85
_FALLBACK_CONFIDENCE_FACTOR = 0.9


def _normalize_verdict(raw: str) -> str:
    """LLM 输出非法 verdict 时归一到 inconclusive (宁可疑勿武断)."""
    verdict = (raw or "").strip().lower()
    return verdict if verdict in _VALID_VERDICTS else VERDICT_INCONCLUSIVE


def _merge_mitre(existing: list[str], incoming: list[str]) -> list[str]:
    """LLM 返回的 MITRE 技术 ID 与已有列表合并去重 (保序)."""
    merged: list[str] = []
    for item in [*(existing or []), *(incoming or [])]:
        tid = (item or "").strip()
        if tid and tid not in merged:
            merged.append(tid)
    return merged


def _build_analyst_messages(state: SecOpsState) -> list[dict[str, str]]:
    """构造研判 prompt: 把证据上下文全部摊给模型."""
    iocs = state.get("iocs") or {}
    intel = state.get("intel_snippets") or []
    mitre = state.get("mitre_techniques") or []

    iocs_text = "\n".join(
        f"- {kind}: {', '.join(values) if isinstance(values, (list, tuple)) else values}"
        for kind, values in iocs.items()
        if values
    ) or "（未提取到 IOC）"

    intel_text = "\n".join(f"- {snip}" for snip in intel) or "（无外部威胁情报）"

    mitre_text = ", ".join(mitre) or "（无预映射）"

    system = (
        "你是资深安全威胁研判分析师 (SecOps Analyst). 基于以下证据对告警做出判定, 只输出 json.\n"
        "研判纪律 (必须遵守):\n"
        "1. 结论必须引用证据: 每个判定都要说明由哪条 IOC / 哪条情报 / 哪个异常模式支撑, "
        "禁止无证据断言.\n"
        "2. 外部威胁情报仅供参考, 不直接定罪: 情报命中只提升置信度, 单独的情报匹配"
        "不足以给出 malicious, 需结合本地异常证据交叉验证 (反幻觉纪律).\n"
        "3. verdict 必须是四态之一: benign | suspicious | malicious | inconclusive. "
        "证据不足时选 inconclusive 而不是猜.\n"
        "4. verdict 与证据强度必须匹配: 例如仅一个可疑 IP 不能直接判 malicious, "
        "应落到 suspicious 或 inconclusive.\n"
        f"5. 当 confidence < {CONFIDENCE_THRESHOLD} 时必须设 needs_more_data=true, "
        "并说明还缺什么证据 (供 Scout 补充调查).\n"
        "6. mitre_techniques 必须有证据支撑, 拿不准就返回空列表."
    )

    critic_feedback = state.get("critic_feedback") or ""
    retry_hint = ""
    if critic_feedback:
        retry_hint = (
            f"\n上一轮研判被审计驳回, 驳回意见如下, 本次研判必须修正:\n{critic_feedback}\n"
        )

    user = (
        f"# 告警原文\n{(state.get('input') or '').strip() or '(空)'}\n\n"
        f"# 告警类型\n{state.get('alert_type') or 'unknown'}\n\n"
        f"# 初判严重度\n{state.get('severity') or '未知'}\n\n"
        f"# 提取的 IOC\n{iocs_text}\n\n"
        f"# 异常评分\n{state.get('anomaly_score', 0.0)} — {state.get('anomaly_reason') or '无描述'}\n\n"
        f"# 外部威胁情报 (仅供参考, 不直接定罪)\n{intel_text}\n\n"
        f"# 预映射 MITRE 技术\n{mitre_text}\n\n"
        f"# 调查回环轮次\n{state.get('loop_count', 0)} / 上限 3\n"
        f"{retry_hint}\n"
        "请给出威胁评估、置信度与四态判定."
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


async def analyst_node(state: SecOpsState) -> dict:
    """研判核心节点: 威胁评估 + 置信度 + verdict 四态.

    Returns (写入 state):
        assessment:            威胁评估文本 (schema.threat_assessment)
        confidence:            研判置信度 0.0-1.0
        verdict:               四态判定
        verdict_reason:        判定依据
        mitre_techniques:      LLM 返回与已有合并去重
        investigation_pending: needs_more_data 临时字段 (graph 路由用)
        loop_count:            需要回环时 +1

    LLM 失败 fail-soft: confidence = anomaly_score * 0.9 (封顶 0.85),
    verdict='inconclusive', 不中断流程.
    """
    anomaly_score = float(state.get("anomaly_score") or 0.0)
    existing_mitre = list(state.get("mitre_techniques") or [])
    loop_count = int(state.get("loop_count") or 0)

    try:
        harness = get_agent_harness()
        router_model = harness.router_model()
        llm = get_chat_llm(model=router_model, temperature=0, timeout=60, max_retries=1)
        decision: AnalystAssessment = await ainvoke_structured(
            llm=llm,
            schema_cls=AnalystAssessment,
            messages=_build_analyst_messages(state),
            model_name=router_model,
        )
    except Exception as e:
        # fail-soft 兑底: 不中断, 给出基于异常分的保守评估
        fallback_conf = min(anomaly_score * _FALLBACK_CONFIDENCE_FACTOR, _FALLBACK_CONFIDENCE_CAP)
        detail = f"{type(e).__name__}: {e}"
        logger.warning(f"[Analyst] 研判 LLM 失败, 基于异常分保守评估 (conf={fallback_conf:.2f}): {e}")
        return {
            "assessment": "研判 LLM 失败，基于异常分的保守评估",
            "confidence": round(fallback_conf, 4),
            "verdict": VERDICT_INCONCLUSIVE,
            "verdict_reason": f"LLM 研判不可用, 仅以异常分 {anomaly_score} 做保守评估 ({detail})",
            "mitre_techniques": existing_mitre,
            # LLM 不可用 ≠ 证据不足: 服务故障不触发调查回环 (回环只会再超时烧 token),
            # 直接进 Critic/Reporter 用保守评估收尾
            "investigation_pending": False,
            "loop_count": loop_count,
            "error": f"analyst_llm_failed: {detail}",
        }

    verdict = _normalize_verdict(decision.verdict)
    confidence = float(decision.confidence or 0.0)
    needs_more_data = bool(decision.needs_more_data) and confidence < CONFIDENCE_THRESHOLD

    logger.info(
        f"[Analyst] verdict={verdict} confidence={confidence:.2f} "
        f"needs_more_data={needs_more_data} | {(decision.verdict_reason or '')[:120]}"
    )

    return {
        "assessment": decision.threat_assessment,
        "confidence": confidence,
        "verdict": verdict,
        "verdict_reason": decision.verdict_reason or "",
        "mitre_techniques": _merge_mitre(existing_mitre, decision.mitre_techniques),
        "investigation_pending": needs_more_data,
        "loop_count": loop_count + 1 if needs_more_data else loop_count,
    }
