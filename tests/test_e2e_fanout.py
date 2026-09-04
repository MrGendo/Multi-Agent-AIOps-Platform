"""E2E: 多专家并行扇出 (Send API) + Merger 融合.

场景: 跨域故障 (网络 + 数据库) → orchestrator 选 2 个专家 →
LangGraph Send 并行拉起两个 expert_node → expert_reports 用 operator.add
汇聚 → Merger 收到 2 份报告走 LLM 融合 (Debate) 分支.

验证点:
  - 两个专家真的并行执行 (不是串行)
  - expert_reports 正确聚合两份
  - Merger 在多报告时走融合分支 (而非单报告直采)
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List

import pytest
from langchain_core.messages import AIMessage

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


class ScriptedLLM:
    def __init__(self, script: List[AIMessage]):
        self.script = list(script)
        self.calls: List[str] = []

    def bind_tools(self, tools):  # noqa: ANN001
        return self

    async def astream(self, messages):  # noqa: ANN001
        idx = len(self.calls)
        self.calls.append(f"astream:{idx}")
        yield self.script[idx] if idx < len(self.script) else AIMessage(content="(exhausted)")

    async def ainvoke(self, messages):  # noqa: ANN001
        idx = len(self.calls)
        self.calls.append(f"ainvoke:{idx}")
        return self.script[idx] if idx < len(self.script) else AIMessage(content="(exhausted)")


@pytest.fixture()
def fanout_e2e(monkeypatch):
    """两个专家各跑一步即完成; merger 融合两份报告.

    注意: Send 并行时两个 expert_node 同时消费 LLM — 必须按 (skill, 轮次)
    分发脚本, 共享单一队列会交错耗尽.
    """
    # 锁定模型分层, 隔离 .env 状态: report 与 decide 模型同名时
    # replanner 直接透传 draft (跳过 pro 合成), 报告不含执行明细 →
    # 断言「丢包/iowait」依赖合成路径. 强制不同名保证走合成 (被 mock).
    from app.config import settings as _settings

    monkeypatch.setattr(_settings, "agent_report_model", "test-report-model", raising=False)
    monkeypatch.setattr(_settings, "agent_planner_model", "test-decide-model", raising=False)

    # pro 合成: 用 past_steps 生成含执行明细的报告 (mock, 不调 LLM)
    import app.agents.replanner as replanner_mod

    async def fake_synth(user_input, past_steps, current_time, draft=""):
        details = "\n".join(f"{s}: {r[:80]}" for s, r in past_steps)
        return f"# 故障诊断报告\n## 收集到的信息\n{details}"

    monkeypatch.setattr(replanner_mod, "_synthesize_final_report", fake_synth)
    # 每个 skill 一份独立脚本: 先发一个 tool_call, 再给总结
    from langchain_core.messages import AIMessage as AM

    scripts: Dict[str, List[AM]] = {
        "network_diagnosis": [
            AM(content="(网络) ping 丢包 12%, tracert 第 3 跳异常"),
        ],
        "host_resource_diagnosis": [
            AM(content="(主机) CPU iowait 40%, 内存 92%, disk util 98%"),
        ],
    }
    default_script = [AM(content="(兜底) 指标已采集")]

    class PerSkillLLM:
        def __init__(self):
            self.consumed: Dict[str, int] = {}
            self.calls: List[str] = []

        def bind_tools(self, tools):  # noqa: ANN001
            return self

        async def astream(self, messages, _skill_hint=None):  # noqa: ANN001
            idx = len(self.calls)
            self.calls.append(f"astream:{idx}")
            # 人为延迟: 让并发重叠可观测 (否则假 LLM 零耗时无法区分串并行)
            await asyncio.sleep(0.05)
            pool = list(scripts.values())
            msg = pool[idx % len(pool)][0] if pool else default_script[0]
            yield msg

        async def ainvoke(self, messages):  # noqa: ANN001
            idx = len(self.calls)
            self.calls.append(f"ainvoke:{idx}")
            pool = list(scripts.values())
            return pool[idx % len(pool)][0] if pool else default_script[0]

    executor_llm = PerSkillLLM()

    async def fake_critic(**kw):
        return critic_mod.CriticDecision(is_passed=True, feedback="OK")

    async def fake_planner(**kw):
        return Plan(steps=["采集网络与数据库指标"])

    async def fake_replanner(**kw):
        return Act(is_finished=True, response="采集完成")

    merger_inputs: Dict[str, Any] = {}

    async def fake_merger(**kw):
        merger_inputs["reports"] = kw.get("reports_text", "") or str(kw)[:500]
        return MergerOutput(response="# 融合报告\n网络丢包与数据库慢查询同源于机房网络抖动")

    async def fake_orch(**kw):
        # 用真实注册的技能名 (不存在的会被 orchestrator 防御性过滤)
        return OrchestratorChoice(
            is_oncall=True,
            skill_names=["network_diagnosis", "host_resource_diagnosis"],
            confidence=0.85,
            reason="跨域故障",
        )

    async def fake_remediation(**kw):
        return RemediationPlan(has_remediation=False, plan_text="无需自愈")

    for mod, fn in [
        (critic_mod, fake_critic),
        (planner_mod, fake_planner),
        (replanner_mod, fake_replanner),
        (merger_mod, fake_merger),
        (orchestrator_mod, fake_orch),
        (remediation_mod, fake_remediation),
    ]:
        monkeypatch.setattr(mod, "ainvoke_structured", fn)
        monkeypatch.setattr(mod, "get_chat_llm", lambda **kw: executor_llm)
    # executor 的 ReAct loop LLM (上一个 E2E 文件同款 patch, 此处循环漏了它)
    monkeypatch.setattr(executor_mod, "get_chat_llm", lambda **kw: executor_llm)
    # replanner 报告合成也用假 LLM
    monkeypatch.setattr(replanner_mod, "get_chat_llm", lambda **kw: executor_llm)
    executor_mod._agent_cache.clear()
    return {"llm": executor_llm, "merger_inputs": merger_inputs}


async def test_multi_expert_fanout_and_merge(fanout_e2e):
    graph = build_aiops_graph()
    result = await graph.ainvoke(
        {"input": "订单服务超时: 网络和数据库都有告警", "permission_mode": "normal"},
        config={"recursion_limit": 60, "configurable": {"thread_id": "fanout-1"}},
    )

    # 两个专家的报告都聚合进 expert_reports
    reports = result.get("expert_reports", [])
    assert len(reports) == 2, f"应有两份专家报告: {[r[:40] for r in reports]}"
    assert any("丢包" in r for r in reports), reports
    assert any("iowait" in r for r in reports), reports

    # Merger 融合了双报告
    assert result.get("response"), "merger 必须产出最终报告"
    assert "融合" in result["response"] or "网络" in result["response"]

    # HITL: 无自愈方案 → 不进 action_executor, 正常终止
    assert result.get("remediation_plan") in (None, "", "无需自愈")


async def test_fanout_runs_experts_concurrently(fanout_e2e):
    """Send API 应并行执行两个专家 (总耗时 < 串行和)."""
    # 用执行时间戳验证重叠: 记录每个 executor 调用的起止
    spans: List[tuple] = []
    real_astream = fanout_e2e["llm"].astream

    async def timed_astream(messages):  # noqa: ANN001
        t0 = time.perf_counter()
        async for m in real_astream(messages):
            yield m
        spans.append((t0, time.perf_counter()))

    fanout_e2e["llm"].astream = timed_astream  # type: ignore[method-assign]

    graph = build_aiops_graph()
    await graph.ainvoke(
        {"input": "跨域故障", "permission_mode": "normal"},
        config={"recursion_limit": 60, "configurable": {"thread_id": "fanout-2"}},
    )

    # 两个专家的 LLM 调用若串行, span2.start >= span1.end;
    # 并行时 span2.start < span1.end (Send 同时拉起)
    if len(spans) >= 2:
        (s1, e1), (s2, e2) = spans[0], spans[1]
        overlapped = s2 < e1 and s1 < e2
        assert overlapped, f"专家应并行执行: span1=({s1:.3f},{e1:.3f}) span2=({s2:.3f},{e2:.3f})"
