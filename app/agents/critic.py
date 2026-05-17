"""Critic 节点 (Phase 5): 对 Executor 收集的信息进行微观校验防幻觉。

主要工作:
- 获取 past_steps[-1] (刚才 Executor 生成的结果)
- 使用较快的 Router 模型 (qwen-turbo 或 flash) 进行评审
- 判断是否存在明显的幻觉、代码执行报错等
- 如果通过，critic_passed = True
- 如果驳回，critic_passed = False，带着 feedback 供 Executor 下一次重试
"""

from __future__ import annotations

from loguru import logger
from pydantic import BaseModel, Field

from app.agents.state import PlanExecuteState
from app.core.llm import get_chat_llm
from app.core.structured import ainvoke_structured
from app.runtime.agent_harness import get_agent_harness
from app.runtime.transitions import make_transition


class CriticDecision(BaseModel):
    is_passed: bool = Field(description="是否通过校验？如果结果中带有明显的工具执行报错、脚本崩溃异常，或者内容明显属于大模型的捏造（例如没有调用工具就得出了具体指标），则为 false。如果只是没有查出问题，但工具执行正常，应该算 true。")
    feedback: str = Field(description="驳回理由或修改建议。如果通过，可以直接返回 'OK'。")


async def critic_node(state: PlanExecuteState) -> PlanExecuteState:
    """对最后一次执行结果进行校验。"""
    past_steps = state.get("past_steps", [])
    if not past_steps:
        # 没有执行过任何步骤，直接通过
        return {"critic_passed": True, "critic_feedback": ""}
        
    last_step, last_result = past_steps[-1]
    
    harness = get_agent_harness()
    # 使用较快的模型 (与 planner 一致)
    model = harness.planner_model()
    llm = get_chat_llm(model=model, temperature=0, timeout=15, max_retries=1)
    
    system_prompt = """你是一个严苛的系统运维评审员 (Critic Agent)。
你需要审查 Executor 提交的最新诊断步骤和结果。
主要检查：
1. 是否有 Python 脚本或工具执行异常/报错的明确信息（例如 SyntaxError, ConnectionRefusedError 等）？如果有，说明脚本需要修改，结果无效。
2. Executor 是否存在捏造数据的情况（幻觉）？比如明显未执行相关查询工具就给出了精确的各项数据指标。
如果上述存在问题，请将 is_passed 设为 false，并在 feedback 中指出问题并给出下一步调整建议（例如：“你的脚本在第 3 行报了 NameError，请修正变量名后重试” 或 “你没有调用数据库查询工具，不要捏造指标，请实际调用相关工具”）。
如果你认为执行过程基本合理，没有致命错误（即便没有排查出具体根因，只要逻辑不荒谬），请设置 is_passed 为 true。
"""
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"目标步骤：{last_step}\n\n执行结果与总结：\n{last_result}"}
    ]
    
    try:
        decision = await ainvoke_structured(
            llm=llm,
            schema_cls=CriticDecision,
            messages=messages,
            model_name=model
        )
    except Exception as e:
        logger.warning(f"[Critic] LLM 评审失败，默认放行: {e}")
        # 如果 LLM 异常，为了不阻塞流程，默认放行
        return {"critic_passed": True, "critic_feedback": ""}
        
    logger.info(f"[Critic] 评审完成: passed={decision.is_passed}, feedback={decision.feedback}")
    
    transition = make_transition(
        "critic", 
        "CRITIC_OK" if decision.is_passed else "CRITIC_REJECTED", 
        decision.feedback[:100]
    )
    
    return {
        "critic_passed": decision.is_passed,
        "critic_feedback": decision.feedback if not decision.is_passed else "",
        "transition_history": [transition]
    }
