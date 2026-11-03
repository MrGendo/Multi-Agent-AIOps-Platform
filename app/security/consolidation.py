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


def delete_experiences(content_contains: str = "", all_experiences: bool = False) -> int:
    """删除研判经验 — 经验库治理通道 (此前只进不出, 评测污染经验永久留存).

    Args:
        content_contains: 删除内容含该关键词的经验条目 (如 "RFC 保留段" 清评测
            污染经验 — session_id 等 metadata 在建表后追加会被 Milvus 静默丢弃,
            按会话过滤不可行, 只能按内容匹配)
        all_experiences:  删除全部经验 (慎用)
    Returns:
        删除条数; Milvus 不可用/无底层客户端 → -1 (fail-soft, 调用方提示重试).
    """

    from app.config import settings as _settings

    if not content_contains and not all_experiences:
        return 0
    try:
        # 复用进程级单例 (lifespan 已连接) — 新建实例会另起 lite server,
        # 与既有单例的端口记录冲突导致连接失败
        from app.core.milvus import milvus_manager as mgr

        mgr.connect()  # 幂等; 未连接时 (如离线脚本调用) 自行建立
        client = mgr.raw_client
        if client is None:
            return -1
        # 独立连接的 collection 处于 released 态, query 前必须加载 (幂等)
        client.load_collection(_settings.milvus_collection)
        rows = client.query(
            collection_name=_settings.milvus_collection,
            filter=f'source == "{SECOPS_EXP_SOURCE}"',
            output_fields=["pk", "content"],
            limit=1000,
        )
        if all_experiences:
            pks = [r["pk"] for r in rows if "pk" in r]
        else:
            pks = [r["pk"] for r in rows
                   if "pk" in r and content_contains in (r.get("content") or "")]
        if not pks:
            return 0
        client.delete(
            collection_name=_settings.milvus_collection,
            filter=f'pk in {pks}',
        )
        logger.info(
            f"[SecConsolidation] 经验治理: 删除 {len(pks)} 条 "
            f"({'全部' if all_experiences else f'内容含「{content_contains}」'})"
        )
        return len(pks)
    except Exception as e:
        logger.warning(f"[SecConsolidation] 经验删除失败 (fail-soft): {e}")
        return -1


EMAIL_EXP_SOURCE = "email_experience"


async def consolidate_email_verdict(
    raw_email_excerpt: str, verdict_summary: str
) -> None:
    """邮件研判经验提炼 — 仅 phishing 判定调用 (benign/suspicious 不入库, 与告警侧
    「无沉淀价值不入库」同纪律防噪声). 从不抛异常 (fire-and-forget 安全).

    Args:
        raw_email_excerpt: 邮件 headers + 正文节选 (复用 analyze_email 的截断口径)
        verdict_summary: 判定摘要 (classification/phishing_type/关键 indicators)
    """
    logger.info("[EmailConsolidation] 开始提炼邮件研判经验")
    try:
        harness = get_agent_harness()
        model = harness.planner_model()
        llm = get_chat_llm(model=model, temperature=0.1, timeout=120, max_retries=2)
        system_prompt = (
            "你是邮件安全研判专家 (Email Security Analyst Mentor). 任务: 把一次钓鱼邮件 "
            "研判结论提炼为精简的 <Threat Pattern> 经验文档, 供后续同类邮件研判参考. "
            "提取攻击话术、仿冒手法、诱饵特征与鉴别要点. 证据不足或无实质鉴别价值时 "
            "设置 is_valid_threat = false."
        )
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"邮件节选:\n{raw_email_excerpt}\n\n判定摘要:\n{verdict_summary}"},
        ]
        pattern = await ainvoke_structured(
            llm=llm, schema_cls=ThreatPattern, messages=messages, model_name=model
        )
    except Exception as e:
        logger.warning(f"[EmailConsolidation] LLM 提炼失败 (fail-soft 忽略): {e}")
        return

    if not pattern.is_valid_threat:
        logger.info("[EmailConsolidation] 判定为无沉淀价值, 忽略入库")
        return

    doc_content = (
        f"# {pattern.title}\n\n"
        f"(钓鱼邮件研判经验)\n\n"
        f"## 攻击话术与手法\n{pattern.attack_pattern}\n\n"
        f"## 诱饵与指标特征\n{pattern.indicators}\n\n"
        f"## 鉴别要点\n{pattern.verdict_rationale}\n\n"
        f"## 处置建议\n{pattern.recommended_actions}\n"
    )
    try:
        chunks = split_markdown(doc_content, source=EMAIL_EXP_SOURCE)
        for chunk in chunks:
            meta = chunk.metadata or {}
            # 同 alert 侧: Milvus 按首批文档建 schema, 缺键非法 — 显式补齐
            meta.setdefault("h1", "")
            meta.setdefault("h2", "")
            meta.setdefault("h3", "")
            meta["type"] = "email_threat_pattern"
            chunk.metadata = meta
        vs = get_vector_store()
        vs.add_documents(chunks)
        logger.info(f"[EmailConsolidation] 邮件研判经验已入库: {pattern.title}")
    except Exception as e:
        logger.warning(f"[EmailConsolidation] 入库失败 (fail-soft): {e}")
