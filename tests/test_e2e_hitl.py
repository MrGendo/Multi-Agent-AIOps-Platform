"""E2E: HITL 人机共驾 — interrupt_before action_executor 审批流.

场景: 诊断产出可自愈方案 → 图在 action_executor 前中断 (HITL) →
人类批准 (update_state remediation_approved=True) → resume →
action_executor 真实执行并追加结果到报告.

验证点:
  - 图确实停在 action_executor 之前 (interrupt 生效)
  - 未批准时执行被强制终止 (防御: 到达执行节点但未授权)
  - 批准后 resume, 自愈结果追加进最终报告
"""

from __future__ import annotations

from typing import List

import pytest
from langchain_core.messages import AIMessage

import app.agents.action_executor as action_mod
import app.agents.critic as critic_mod
import app.agents.executor as executor_mod
import app.agents.merger as merger_mod
import app.agents.orchestrator as orchestrator_mod
import app.agents.planner as planner_mod
import app.agents.remediation_planner as remediation_mod
import app.agents.replanner as replanner_mod
from app.agents.graph import build_aiops_graph
from app.agents.merger import MergerOutput
from app.agents.orchestrator import OrchestratorChoice
from app.agents.remediation_planner import RemediationPlan
from app.agents.state import Act, Plan


class NoopLLM:
    def bind_tools(self, tools):  # noqa: ANN001
        return self

    async def astream(self, messages):  # noqa: ANN001
        yield AIMessage(content="指标已采集")

    async def ainvoke(self, messages):  # noqa: ANN001
        return AIMessage(content="指标已采集")


@pytest.fixture()
def hitl_e2e(monkeypatch):
    noop = NoopLLM()

    async def fake_critic(**kw):
        return critic_mod.CriticDecision(is_passed=True, feedback="OK")

    async def fake_planner(**kw):
        return Plan(steps=["采集指标"])

    async def fake_replanner(**kw):
        return Act(is_finished=True, response="根因: 内存泄漏")

    async def fake_merger(**kw):
        return MergerOutput(response="# 诊断报告\n根因: 进程内存泄漏, 建议重启 worker")

    async def fake_orch(**kw):
        return OrchestratorChoice(
            is_oncall=True, skill_names=["generic_oncall"], confidence=0.9, reason="通用"
        )

    async def fake_remediation(**kw):
        # 这次给出可自愈方案 → route_after_remediation 会进 action_executor
        return RemediationPlan(
            has_remediation=True, plan_text="重启 order-worker 容器并观察 5 分钟"
        )

    for mod, fn in [
        (critic_mod, fake_critic),
        (planner_mod, fake_planner),
        (replanner_mod, fake_replanner),
        (merger_mod, fake_merger),
        (orchestrator_mod, fake_orch),
        (remediation_mod, fake_remediation),
    ]:
        monkeypatch.setattr(mod, "ainvoke_structured", fn)
        monkeypatch.setattr(mod, "get_chat_llm", lambda **kw: noop)
    monkeypatch.setattr(executor_mod, "get_chat_llm", lambda **kw: noop)
    executor_mod._agent_cache.clear()

    # 加速: action_executor 里的模拟 sleep 缩短 (函数内 import asyncio)
    import app.agents.action_executor as action_mod
    import asyncio as real_asyncio

    real_sleep = real_asyncio.sleep

    async def fast_sleep(sec):  # noqa: ANN001
        await real_sleep(0.01)

    monkeypatch.setattr(real_asyncio, "sleep", fast_sleep)
    return {}


CFG = {"recursion_limit": 60, "configurable": {"thread_id": "hitl-1"}}


async def test_hitl_interrupt_then_approve(hitl_e2e):
    graph = build_aiops_graph()

    # 第一段: 诊断 + 自愈计划 → 应停在 action_executor 前
    state1 = await graph.ainvoke(
        {"input": "订单服务内存泄漏告警", "permission_mode": "normal"}, config=CFG
    )
    assert state1.get("remediation_plan") == "重启 order-worker 容器并观察 5 分钟"

    # 图中断在 action_executor (interrupt_before), 尚未执行
    snapshot = await graph.aget_state(CFG)
    assert snapshot.next, "图应停在中断点等待人工审批"
    assert "action_executor" in snapshot.next

    # 人类批准 → 注入授权 → resume
    await graph.aupdate_state(CFG, {"remediation_approved": True})
    state2 = await graph.ainvoke(None, config=CFG)

    # 自愈执行结果追加进最终报告
    final = state2.get("response", "")
    assert "已授权执行" in final or "自愈" in final, final[-200:]


async def test_hitl_reject_blocks_execution(hitl_e2e):
    """未批准直接 resume → action_executor 防御性拒绝."""
    graph = build_aiops_graph()

    state1 = await graph.ainvoke(
        {"input": "订单服务内存泄漏告警", "permission_mode": "normal"},
        config={"recursion_limit": 60, "configurable": {"thread_id": "hitl-2"}},
    )
    cfg2 = {"recursion_limit": 60, "configurable": {"thread_id": "hitl-2"}}

    # 明确不批准
    await graph.aupdate_state(cfg2, {"remediation_approved": False})
    state2 = await graph.ainvoke(None, config=cfg2)

    # 防御生效: 未授权 → 不执行, remediation_plan 被标记失败
    assert "未获得授权" in state2.get("remediation_plan", ""), state2.get("remediation_plan")
    final = state2.get("response", "")
    assert "已授权执行" not in final
