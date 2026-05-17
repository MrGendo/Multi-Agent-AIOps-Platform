"""LangGraph 图编排 (Phase 2 并行多专家重构版).

图结构:

    [START]
       │
       ▼
   ┌────────────────┐
   │ Orchestrator   │ (分析输入，选出多个专家)
   └───────┬────────┘
           ▼ (Send 扇出)
   ┌────────────────┐
   │  Expert Nodes  │ (并行执行子图: Planner -> Executor <-> Replanner)
   └───────┬────────┘
           ▼
   ┌────────────────┐
   │    Merger      │ (综合多专家报告，输出最终 response)
   └───────┬────────┘
           ▼
   ┌──────────────────────────┐
   │ Remediation Planner      │ (提议修复计划)
   └───────┬──────────────────┘
           ▼
   ┌──────────────────────────┐
   │ Action Executor (HITL)   │ (执行修复，生成终态)
   └───────┬──────────────────┘
           ▼
         [END]
"""

from typing import Literal

from langgraph.checkpoint.memory import MemorySaver
from langgraph.constants import Send
from langgraph.graph import END, START, StateGraph
from loguru import logger

from app.agents.action_executor import action_executor_node
from app.agents.executor import execute_node
from app.agents.planner import plan_node
from app.agents.remediation_planner import remediation_planner_node
from app.agents.replanner import replan_node
from app.agents.orchestrator import orchestrator_node
from app.agents.merger import merger_node
from app.agents.critic import critic_node
from app.agents.state import PlanExecuteState


# =====================================================================
# 子图：Expert Subgraph (单专家的 Plan-Execute-Replan 闭环)
# =====================================================================

def expert_should_end(state: PlanExecuteState) -> Literal["executor", "planner", "__end__"]:
    response = state.get("response", "")
    if response:
        return END
    if state.get("pending_reroute"):
        return "planner"
    if not state.get("plan"):
        return END
    return "executor"


def route_after_critic(state: PlanExecuteState) -> Literal["executor", "replanner"]:
    if state.get("critic_passed", True):
        return "replanner"
    return "executor"


def build_expert_subgraph():
    workflow = StateGraph(PlanExecuteState)
    workflow.add_node("planner", plan_node)
    workflow.add_node("executor", execute_node)
    workflow.add_node("critic", critic_node)
    workflow.add_node("replanner", replan_node)

    workflow.add_edge(START, "planner")
    workflow.add_edge("planner", "executor")
    workflow.add_edge("executor", "critic")
    workflow.add_conditional_edges(
        "critic",
        route_after_critic,
        {
            "executor": "executor",
            "replanner": "replanner",
        }
    )
    workflow.add_conditional_edges(
        "replanner",
        expert_should_end,
        {
            "executor": "executor",
            "planner": "planner",
            END: END,
        },
    )
    return workflow.compile()


async def expert_node(state: PlanExecuteState) -> dict:
    """包装专家子图的执行，提取 response 放入 expert_reports。"""
    subgraph = build_expert_subgraph()
    logger.info(f"[ExpertNode] 开始执行专家子图: {state.get('selected_skill')}")
    try:
        # recursion_limit 设大点防止子图提前中断
        result = await subgraph.ainvoke(state, config={"recursion_limit": 50})
        response = result.get("response", "该专家未生成有效报告")
        return {
            "expert_reports": [response],
            "transition_history": result.get("transition_history", [])
        }
    except Exception as e:
        logger.exception(f"[ExpertNode] 专家子图执行异常: {e}")
        return {
            "expert_reports": [f"专家执行异常: {e}"]
        }


# =====================================================================
# 主图：Main AIOps Graph (Orchestrator -> 并行专家 -> Merger -> 修复)
# =====================================================================

def route_after_orchestrator(state: PlanExecuteState):
    """Orchestrator 之后，判断是直接结束还是扇出(Send)给多个专家。"""
    response = state.get("response", "")
    if response:
        # 如果 Orchestrator 已经给出了 response (如 out of scope)，直接跳到后面
        # 这里为了保持逻辑一致，我们直接跳过专家和 Merger，进入 remediation (通常会跳过)
        return "remediation_planner"

    skills = state.get("selected_skills", [])
    if not skills:
        return "remediation_planner"

    # Send API 并行拉起多个 expert_node
    return [Send("expert_node", {
        "input": state.get("input", ""),
        "selected_skill": skill,
        "permission_mode": state.get("permission_mode", "")
    }) for skill in skills]


def route_after_remediation(state: PlanExecuteState) -> Literal["action_executor", "__end__"]:
    plan = state.get("remediation_plan", "")
    if plan and plan != "无需自愈":
        return "action_executor"
    return END


def build_aiops_graph():
    """构建 AIOps 主图."""
    workflow = StateGraph(PlanExecuteState)

    workflow.add_node("orchestrator", orchestrator_node)
    workflow.add_node("expert_node", expert_node)
    workflow.add_node("merger", merger_node)
    workflow.add_node("remediation_planner", remediation_planner_node)
    workflow.add_node("action_executor", action_executor_node)

    workflow.add_edge(START, "orchestrator")
    
    workflow.add_conditional_edges(
        "orchestrator",
        route_after_orchestrator,
        ["expert_node", "remediation_planner"]
    )
    
    workflow.add_edge("expert_node", "merger")
    workflow.add_edge("merger", "remediation_planner")
    
    workflow.add_conditional_edges(
        "remediation_planner",
        route_after_remediation,
        {
            "action_executor": "action_executor",
            END: END,
        }
    )
    workflow.add_edge("action_executor", END)

    memory = MemorySaver()
    compiled = workflow.compile(
        checkpointer=memory,
        interrupt_before=["action_executor"]
    )
    logger.info("[Graph] Phase 2: 并行多专家主图编译完成")
    return compiled
