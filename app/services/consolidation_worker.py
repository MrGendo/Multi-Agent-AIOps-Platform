"""经验提炼与内化 (Consolidation Worker)

负责将 AIOps 的最终诊断报告提炼为精简的 Root Cause Pattern,
并向量化存入 Milvus, 作为后续排查的历史经验参考。
"""

from __future__ import annotations

import asyncio
from loguru import logger
from pydantic import BaseModel, Field

from app.core.llm import get_chat_llm
from app.core.structured import ainvoke_structured
from app.core.vector_store import get_vector_store
from app.runtime.agent_harness import get_agent_harness
from app.utils.splitter import split_markdown

class ExperiencePattern(BaseModel):
    is_valid_incident: bool = Field(description="是否是一次真实的故障排查（如果只是闲聊或咨询，应为 false）")
    title: str = Field(description="经验库标题，例如：Redis 内存 OOM 导致接口超时")
    symptoms: str = Field(description="故障现象描述")
    root_cause: str = Field(description="根因分析")
    remediation: str = Field(description="有效的处置策略或止损方案")

async def consolidate_diagnosis_report(session_id: str, user_input: str, final_report: str) -> None:
    """后置异步触发：提炼经验并存入向量库"""
    if not final_report:
        return
        
    logger.info(f"[Consolidation] 开始提炼经验 session={session_id}")
    
    # 1. 调用大模型提炼
    harness = get_agent_harness()
    model = harness.planner_model()
    llm = get_chat_llm(model=model, temperature=0.1, timeout=60, max_retries=1)
    
    system_prompt = """你是一个经验丰富的 SRE 专家。
你的任务是将一份冗长的故障排查报告，提炼为一份精简的 <Root Cause Pattern> 经验文档。
要求提取核心现象、根因、以及被验证有效的处置建议。
如果该报告并未查出根因，或只是一次普通的问答咨询，请设置 is_valid_incident = false。"""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"用户初始输入：\n{user_input}\n\n最终诊断报告：\n{final_report}"}
    ]
    
    try:
        pattern = await ainvoke_structured(
            llm=llm,
            schema_cls=ExperiencePattern,
            messages=messages,
            model_name=model
        )
    except Exception as e:
        logger.error(f"[Consolidation] LLM 提炼失败: {e}")
        return
        
    if not pattern.is_valid_incident:
        logger.info("[Consolidation] 该报告被判定为非典型故障或无效记录，忽略入库")
        return
        
    # 2. 格式化并入库
    doc_content = f"""# {pattern.title}

## 故障现象
{pattern.symptoms}

## 根因分析
{pattern.root_cause}

## 处置建议
{pattern.remediation}
"""
    
    # 使用固定 source 标记这是经验库数据
    source_name = "experience_db"
    chunks = split_markdown(doc_content, source=source_name)
    
    try:
        for chunk in chunks:
            chunk.metadata["session_id"] = session_id
            chunk.metadata["type"] = "historical_experience"
        
        vs = get_vector_store()
        vs.add_documents(chunks)
        logger.info(f"[Consolidation] 经验已内化并存入向量库！标题: {pattern.title}")
    except Exception as e:
        logger.error(f"[Consolidation] 入库失败: {e}")
