from __future__ import annotations

from loguru import logger
from pydantic import BaseModel, Field

from app.agents.state import PlanExecuteState
from app.core.llm import get_chat_llm
from app.core.structured import ainvoke_structured
from app.runtime.agent_harness import get_agent_harness
from app.runtime.transitions import make_transition

class MergerOutput(BaseModel):
    response: str = Field(..., description="融合后的最终诊断报告，格式必须是 Markdown。综合各个专家的结论，给出最终的根因分析和处置建议。如果各个专家的报告有冲突，你需要自行辨别并解决冲突（Debate）。")

async def merger_node(state: PlanExecuteState) -> PlanExecuteState:
    """Merger 节点: 等待所有并行的专家子图完成后，汇总它们的报告并输出最终报告。"""
    expert_reports = state.get("expert_reports", [])
    
    if not expert_reports:
        logger.warning("[Merger] 没有收到任何专家的报告")
        return {"response": "由于未知原因，各个领域的专家未能提供诊断报告。"}

    if len(expert_reports) == 1:
        logger.info("[Merger] 只有一个专家报告，直接采用")
        return {"response": expert_reports[0]}
        
    logger.info(f"[Merger] 收到 {len(expert_reports)} 份专家报告，正在进行融合 (Debate) ...")
    
    harness = get_agent_harness()
    model_name = harness.planner_model()  # 使用高级模型做综合
    llm = get_chat_llm(model=model_name, temperature=0, timeout=60, max_retries=1)

    reports_text = "\n\n".join([f"=== 专家报告 {i+1} ===\n{r}" for i, r in enumerate(expert_reports)])
    
    system_prompt = (
        "你是一个资深的 SRE（站点可靠性工程师）架构师。\n"
        "目前系统发生了一个故障，我派出了多名垂直领域的专家（例如网络专家、数据库专家等）去排查，"
        "并收集到了他们各自的诊断报告。\n\n"
        "你的任务是：\n"
        "1. 阅读并理解所有专家的报告。\n"
        "2. 综合各方结论，撰写一份统一的最终故障诊断报告（Markdown 格式）。\n"
        "3. **解决冲突**：如果不同专家的报告存在矛盾（例如 A 专家认为正常，B 专家认为异常），"
        "你需要基于最确凿的证据来解决冲突，找出真正的根因。\n"
        "4. 最终报告的格式应包含：【问题概述】、【根因分析】、【排查过程】、【修复建议】。"
    )
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"以下是各个专家独立排查后得出的报告，请进行综合：\n\n{reports_text}"}
    ]

    try:
        output = await ainvoke_structured(
            llm=llm,
            schema_cls=MergerOutput,
            messages=messages,
            model_name=model_name,
        )
        final_report = output.response
        logger.info("[Merger] 融合完成")
        transition = make_transition("merger", "merger_ok", f"Merged {len(expert_reports)} reports")
        return {
            "response": final_report,
            "transition_history": [transition]
        }
    except Exception as e:
        logger.exception(f"[Merger] LLM 融合失败: {e}")
        fallback_report = f"# 多专家诊断报告 (未融合)\n\n由于合并失败，以下是各专家的原始结论：\n\n{reports_text}"
        transition = make_transition("merger", "merger_failed", f"Merge failed: {e}")
        return {
            "response": fallback_report,
            "transition_history": [transition]
        }
