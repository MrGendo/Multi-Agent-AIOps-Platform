"""SecOps 研判经验沉淀 (与 AIOps consolidation_worker 对称).

把安全研判报告提炼为 <Threat Pattern> 向量入库 (source=secops_experience),
下次同类告警由 Analyst 召回参考 — 「越用越准」的对称能力.

纪律:
  - is_valid_threat=false 的 (benign/inconclusive 且无深查价值) 不入库, 防噪声
  - fail-soft: 提炼/入库任一失败只 warning, 不影响主研判流程 (本就是后置异步)
  - 召回结果同样受 recall-never-corroborates 约束 (历史研判不是本次定罪证据)
"""

from __future__ import annotations

from loguru import logger
from pydantic import BaseModel, Field

from app.core.llm import get_chat_llm
from app.core.structured import ainvoke_structured
from app.core.vector_store import get_vector_store
from app.runtime.agent_harness import get_agent_harness
from app.utils.splitter import split_markdown

SECOPS_EXP_SOURCE = "secops_experience"


class ThreatPattern(BaseModel):
    """研判经验的结构化提炼."""

    is_valid_threat: bool = Field(
        description=(
            "是否是一次值得沉淀的安全研判 (真实攻击/可疑行为/有复用价值的误报甄别). "
            "纯噪声、无深查的初筛拦截、证据不足的空报告应为 false"
        )
    )
    title: str = Field(description="经验标题, 例如: SSH 暴力破解 + Tor 出口 IP 的典型研判")
    attack_pattern: str = Field(description="攻击模式/行为特征描述")
    indicators: str = Field(description="关键 IOC 与证据特征 (IP/hash/域名/行为链)")
    verdict_rationale: str = Field(description="当时的判定逻辑与证据强度, 供同类告警对照")
    recommended_actions: str = Field(description="被采纳/建议的处置动作")


async def consolidate_triage_report(
    session_id: str, alert_text: str, fact_sheet: str, verdict: str = ""
) -> None:
    """后置异步: 提炼研判经验并存入向量库 (从不抛异常)."""
    if not fact_sheet:
        return

    logger.info(f"[SecConsolidation] 开始提炼研判经验 session={session_id} verdict={verdict}")

    try:
        harness = get_agent_harness()
        model = harness.planner_model()
        llm = get_chat_llm(model=model, temperature=0.1, timeout=120, max_retries=2)

        system_prompt = (
            "你是一个经验丰富的安全研判专家 (SecOps Analyst Mentor). "
            "你的任务是把一份安全告警研判报告提炼为精简的 <Threat Pattern> 经验文档, "
            "供后续同类告警研判参考. 提取攻击模式、关键指标、判定逻辑与处置建议. "
            "如果该报告只是初筛拦截的噪声/误报且无甄别价值, 或证据不足没有实质结论, "
            "请设置 is_valid_threat = false."
        )
        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": f"告警原文:\n{alert_text}\n\n研判报告:\n{fact_sheet}\n\n最终判定: {verdict or '未知'}",
            },
        ]
        pattern = await ainvoke_structured(
            llm=llm, schema_cls=ThreatPattern, messages=messages, model_name=model
        )
    except Exception as e:
        logger.warning(f"[SecConsolidation] LLM 提炼失败 (fail-soft 忽略): {e}")
        return

    if not pattern.is_valid_threat:
        logger.info(f"[SecConsolidation] 判定为无沉淀价值 ({verdict or '无判定'}), 忽略入库")
        return

    doc_content = (
        f"# {pattern.title}\n\n"
        f"(历史研判判定: {verdict or '未知'})\n\n"
        f"## 攻击模式\n{pattern.attack_pattern}\n\n"
        f"## 关键指标\n{pattern.indicators}\n\n"
        f"## 判定逻辑\n{pattern.verdict_rationale}\n\n"
        f"## 处置建议\n{pattern.recommended_actions}\n"
    )

    try:
        chunks = split_markdown(doc_content, source=SECOPS_EXP_SOURCE)
        for chunk in chunks:
            meta = chunk.metadata or {}
            # Milvus 建表按首批 chunk 的 metadata 键, 后续缺键 = DataNotMatchException
            # (09-04 入库链事故同款). SOP 语料带 h1/h2/h3, 经验文档常无 ### 层,
            # 必须显式补齐三键 (空串合法, 缺键不合法).
            meta.setdefault("h1", "")
            meta.setdefault("h2", "")
            meta.setdefault("h3", "")
            meta["session_id"] = session_id
            meta["type"] = "secops_threat_pattern"
            meta["verdict"] = verdict or ""
            chunk.metadata = meta
        vs = get_vector_store()
        vs.add_documents(chunks)
        logger.info(f"[SecConsolidation] 研判经验已入库: {pattern.title}")
    except Exception as e:
        logger.warning(f"[SecConsolidation] 入库失败 (fail-soft): {e}")
