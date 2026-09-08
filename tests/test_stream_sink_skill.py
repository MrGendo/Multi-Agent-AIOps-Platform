"""stream_sink 事件带专家归属 (skill) 的契约测试.

背景: 多专家 Send 并行时各分支 iteration 都从 1 重数, 前端 DAG 必须靠
(skill, iteration) 复合键分泳道, 所以 step_start / tool_call / step_token
事件都必须携带 skill 字段.

验证点:
  1. set_step(iteration) 单参数旧签名向后兼容, 不炸也不改 skill
  2. 双专家并发时 ContextVar 隔离: 各自 set_step 后 emit, skill 不串扰
  3. 真实 LangGraph Send fanout 下 executor 发出的 step_start 带 skill
     (ContextVar 方案的前提: 每个并行分支跑在独立 Task 里, context 是副本)

离线: LLM 全 mock (get_chat_llm 返回假 LLM, bind_tools/astream 单帧).
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import pytest
from langchain_core.messages import AIMessage

import app.agents.executor as executor_mod
import app.agents.critic as critic_mod
import app.agents.orchestrator as orchestrator_mod
import app.agents.planner as planner_mod
import app.agents.replanner as replanner_mod
from app.agents import stream_sink
from app.agents.graph import build_aiops_graph
from app.agents.orchestrator import OrchestratorChoice
from app.agents.state import Act, Plan


# ============================================================
# 1. set_step 旧签名向后兼容
# ============================================================
async def test_set_step_single_arg_backward_compatible():
    """set_step(5) 单参数调用必须兼容: 只更新步号, 不动 skill."""
    stream_sink._skill_var.set(None)  # 隔离上一个测试的残留
    stream_sink.set_step(5)
    assert stream_sink.get_step() == 5
    assert stream_sink._skill_var.get() is None  # skill 未被动过

    stream_sink.set_step(3, "network_diagnosis")
    stream_sink.set_step(4)  # 旧签名: skill 保持上次的值
    assert stream_sink.get_step() == 4
    assert stream_sink._skill_var.get() == "network_diagnosis"
    stream_sink._skill_var.set(None)  # 清理, 防串到下一个测试


async def test_emit_setdefaults_skill_from_contextvar():
    """emit 时事件未带 skill 则从 ContextVar 补, 显式带过的不覆盖."""
    q: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()
    stream_sink.set_sink(q)
    try:
        stream_sink.set_step(2, "database_diagnosis")
        await stream_sink.emit({"type": "tool_call", "name": "query_metrics"})
        await stream_sink.emit({"type": "step_start", "skill": "explicit_skill"})

        ev1 = q.get_nowait()
        assert ev1["skill"] == "database_diagnosis"
        assert ev1["iteration"] == 2
        ev2 = q.get_nowait()
        assert ev2["skill"] == "explicit_skill"  # 显式值优先, 不被 setdefault 覆盖
    finally:
        stream_sink.set_sink(None)  # type: ignore[arg-type]
        stream_sink._skill_var.set(None)


# ============================================================
# 2. 双专家并发 ContextVar 隔离 (asyncio.Task 各自复制 context)
# ============================================================
async def test_concurrent_tasks_contextvar_isolated():
    """两个 asyncio Task 并发 set_step + emit, skill 各归各, 不串扰.

    这是 ContextVar 方案的核心前提: LangGraph Send 分支以独立 Task 执行,
    Task 启动时复制当前 context, 之后各自的 set 互不可见.
    """
    q: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()
    stream_sink.set_sink(q)

    async def expert_coro(skill: str) -> None:
        stream_sink.set_step(1, skill)
        # 人为延迟让两个 Task 真正并发重叠 (零耗时分不出串并行)
        await asyncio.sleep(0.05)
        await stream_sink.emit({"type": "step_start", "iteration": 1, "step": f"{skill} 第 1 步"})
        await asyncio.sleep(0.02)
        await stream_sink.emit({"type": "tool_call", "name": "query_metrics"})

    try:
        await asyncio.gather(
            expert_coro("network_diagnosis"),
            expert_coro("database_diagnosis"),
        )
        events = [q.get_nowait() for _ in range(4)]
        by_skill: Dict[str, List[Dict[str, Any]]] = {"network_diagnosis": [], "database_diagnosis": []}
        for ev in events:
            by_skill.setdefault(ev["skill"], []).append(ev)
        # 两个 Task 各产出 step_start + tool_call, skill 归属正确
        assert len(by_skill["network_diagnosis"]) == 2, events
        assert len(by_skill["database_diagnosis"]) == 2, events
    finally:
        stream_sink.set_sink(None)  # type: ignore[arg-type]
        stream_sink._skill_var.set(None)


# ============================================================
# 3. 真实 Send fanout: executor 的 step_start 事件带 skill
# ============================================================
class _OneShotLLM:
    """假 LLM: bind_tools 返回自身, astream 单帧 (无 tool_calls, 直接给结论)."""

    def __init__(self):
        self.calls = 0

    def bind_tools(self, tools):  # noqa: ANN001
        return self

    async def astream(self, messages):  # noqa: ANN001
        self.calls += 1
        yield AIMessage(content="(mock) 已完成排查")

    async def ainvoke(self, messages):  # noqa: ANN001
        return AIMessage(content="(mock) 已完成排查")


@pytest.fixture()
def fanout_with_trace(monkeypatch):
    """双专家 fanout, 用真实 sink 队列收集事件 (与 aiops_service 同链路).

    注意不能靠 monkeypatch stream_sink.emit 拦截: executor 顶部
    `from ... import emit as emit_stream` 已绑定原函数引用, patch 模块属性拦不到.
    """
    llm = _OneShotLLM()

    async def fake_orch(**kw):
        return OrchestratorChoice(
            is_oncall=True,
            skill_names=["network_diagnosis", "database_diagnosis"],
            confidence=0.9,
            reason="跨域故障",
        )

    async def fake_planner(**kw):
        return Plan(steps=["采集指标", "定位根因"])

    async def fake_replanner(**kw):
        return Act(is_finished=True, response="单专家结论")

    async def fake_critic(**kw):
        return critic_mod.CriticDecision(is_passed=True, feedback="OK")

    for mod, fn in [
        (orchestrator_mod, fake_orch),
        (planner_mod, fake_planner),
        (replanner_mod, fake_replanner),
        (critic_mod, fake_critic),
    ]:
        monkeypatch.setattr(mod, "ainvoke_structured", fn)
        monkeypatch.setattr(mod, "get_chat_llm", lambda **kw: llm)
    monkeypatch.setattr(executor_mod, "get_chat_llm", lambda **kw: llm)
    executor_mod._agent_cache.clear()

    q: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()
    stream_sink.set_sink(q)
    events: List[Dict[str, Any]] = []

    def drain() -> List[Dict[str, Any]]:
        """graph 跑完后由测试显式调用, 把队列里的事件收进列表."""
        while not q.empty():
            events.append(q.get_nowait())
        return events

    yield {"events": events, "llm": llm, "drain": drain}
    # 无论断言成败都要卸掉 sink, 防串到其他测试
    stream_sink.set_sink(None)  # type: ignore[arg-type]
    stream_sink._skill_var.set(None)


async def test_fanout_step_start_events_carry_skill(fanout_with_trace):
    """真实 Send fanout 下, 两个专家的 step_start 各自带正确 skill."""
    graph = build_aiops_graph()
    await graph.ainvoke(
        {"input": "订单超时: 网络和数据库都有告警", "permission_mode": "normal"},
        config={"recursion_limit": 60, "configurable": {"thread_id": "skill-1"}},
    )
    events = fanout_with_trace["drain"]()

    starts = [e for e in events if e.get("type") == "step_start"]
    skills = {e.get("skill") for e in starts}
    # 两个专家并行, 各自至少发出 1 条带自己 skill 的 step_start
    assert "network_diagnosis" in skills, starts
    assert "database_diagnosis" in skills, starts
    # 每条 step_start 的 skill 都非空 (不允许漏归属)
    assert all(e.get("skill") for e in starts), starts


async def test_fanout_no_skill_bleed_between_experts(fanout_with_trace):
    """tool_call / step_token 不允许带错专家: skill 值只能属于两个专家之一."""
    graph = build_aiops_graph()
    await graph.ainvoke(
        {"input": "跨域故障", "permission_mode": "normal"},
        config={"recursion_limit": 60, "configurable": {"thread_id": "skill-2"}},
    )
    events = fanout_with_trace["drain"]()

    valid = {"network_diagnosis", "database_diagnosis", None, ""}
    for ev in events:
        if ev.get("type") in ("step_start", "tool_call", "step_token"):
            assert ev.get("skill") in valid, ev
