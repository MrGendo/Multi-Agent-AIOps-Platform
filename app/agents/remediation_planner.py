"""Remediation Planner 节点: 在生成诊断报告后，评估是否可以自愈，并提议修复计划。"""

from loguru import logger
from pydantic import BaseModel, Field

from app.agents.state import PlanExecuteState
from app.core.llm import get_chat_llm
from app.core.structured import ainvoke_structured
from app.runtime.agent_harness import get_agent_harness

class RemediationPlan(BaseModel):
    has_remediation: bool = Field(description="是否存在可自愈的修复方案")
    plan_text: str = Field(description="具体的修复计划说明", default="")

async def remediation_planner_node(state: PlanExecuteState) -> PlanExecuteState:
    """评估诊断报告，如果存在建议的自愈操作，则生成修复计划。"""
    user_input = state.get("input", "")
    response = state.get("response", "")
    
    logger.info("[RemediationPlanner] 开始评估修复方案...")
    
    if not response:
        logger.warning("[RemediationPlanner] 无诊断报告，跳过")
        return {"remediation_plan": "无需自愈"}
        
    harness = get_agent_harness()
    # 使用 planner 模型即可，它负责规划
    model = harness.planner_model()
    llm = get_chat_llm(model=model, temperature=0, timeout=30)
    
    system_prompt = """你是一个专业的运维自愈安全评审系统。
基于用户的诊断报告，判断是否需要并可以执行自动化自愈操作（如重启服务、清理磁盘等）。
如果有，提出简明扼要的 1-2 步修复计划。
不要提供破坏性极强的操作（如格式化磁盘、删除数据库）。
如果问题只是单纯的咨询或者不需要机器介入的操作，请设置 has_remediation 为 false。"""
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"【用户问题】\n{user_input}\n\n【诊断报告】\n{response}\n\n请评估是否需要自愈并给出方案。"}
    ]
    
    try:
        plan = await ainvoke_structured(
            llm=llm,
            schema_cls=RemediationPlan,
            messages=messages,
            model_name=model,
        )
    except Exception as e:
        logger.exception(f"[RemediationPlanner] 生成修复方案失败: {e}")
        return {"remediation_plan": "评估修复方案失败，需人工介入"}
        
    if plan.has_remediation and plan.plan_text:
        logger.info(f"[RemediationPlanner] 提议自愈方案: {plan.plan_text}")
        return {
            "remediation_plan": plan.plan_text,
            "remediation_approved": False  # 初始化为未授权
        }
    else:
        logger.info("[RemediationPlanner] 判断无需自愈")
        return {"remediation_plan": "无需自愈"}
