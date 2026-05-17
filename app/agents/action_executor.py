"""Action Executor 节点: 在获得人工授权后，执行自愈操作。"""

from loguru import logger
from app.agents.state import PlanExecuteState

async def action_executor_node(state: PlanExecuteState) -> PlanExecuteState:
    """执行自愈计划。"""
    approved = state.get("remediation_approved", False)
    plan = state.get("remediation_plan", "")
    
    if plan == "无需自愈" or not plan:
        logger.info("[ActionExecutor] 没有有效的自愈计划或无需自愈，跳过执行。")
        return {"remediation_plan": "已跳过"}
        
    if not approved:
        logger.warning("[ActionExecutor] 警告：到达执行节点但未获得授权！强制终止执行。")
        return {"remediation_plan": "未获得授权，执行失败"}
        
    logger.info(f"[ActionExecutor] 已获得授权，正在执行自愈计划: {plan}")
    
    # 这里我们只是模拟执行。实际应用中，这里会调用带有写权限的 Action MCP 
    # 或者执行受限的预置脚本。
    
    # 模拟执行延迟和结果
    import asyncio
    await asyncio.sleep(2)
    
    execution_result = f"已成功执行自愈方案: {plan}。系统目前状态正常。"
    logger.info(f"[ActionExecutor] 执行完毕: {execution_result}")
    
    # 把执行结果追加到 response 中
    current_response = state.get("response", "")
    new_response = current_response + f"\n\n## 六、自愈执行结果\n> **[已授权执行]** {execution_result}"
    
    return {
        "response": new_response,
        "remediation_plan": "执行完毕"
    }
