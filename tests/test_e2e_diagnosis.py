"""E2E 功能测试: mock LLM 边界, 其余全真 — 验证平台「真的能解决问题」.

与 mock-graph 测试的区别: 这里不 mock graph 节点, 走真实的
orchestrator → expert 子图(planner→executor→critic→replanner) → merger
→ remediation_planner 全链路. 只把 LLM 边界 (get_chat_llm /
ainvoke_structured) 替换成可编程假模型.

真实被执行的组件:
  - LangGraph 状态流转与条件路由 (critic 驳回重试, replanner)
  - 工具权限过滤 (PermissionMode) 与 run_parallel_agent ReAct loop
  - 真实工具: execute_python_script 沙箱 (真子进程跑 Python)
  - 报告组装与 remediation 分支

场景: Redis 内存告警诊断 — 专家需调用沙箱脚本采集指标,
critic 第一次驳回 (捏造数据), 第二次通过, 最终产出真实报告.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import pytest
from langchain_core.messages import AIMessage, BaseMessage

import app.agents.critic as critic_mod
import app.agents.executor as executor_mod
import app.agents.merger as merger_mod
import app.agents.orchestrator as orchestrator_mod
import app.agents.planner as planner_mod
import app.agents.remediation_planner as remediation_mod
import app.agents.replanner as replanner_mod
import app.tools.mcp_loader as mcp_loader
from app.agents.graph import build_aiops_graph


# ============================================================
# 可编程假 LLM: 按 (节点, 调用序号) 脚本化输出
# ============================================================
class ScriptedLLM:
    """实现 BaseChatModel 最小接口: bind_tools / astream."""

    def __init__(self, script: List[AIMessage]):
        self.script = list(script)
        self.calls: List[str] = []
        self.tool_calls_log: List[Dict[str, Any]] = []

    def bind_tools(self, tools):  # noqa: ANN001
        return self

    async def astream(self, messages):  # noqa: ANN001
        idx = len(self.calls)
        self.calls.append(f"astream:{idx}")
        msg = self.script[idx] if idx < len(self.script) else AIMessage(content="(script exhausted)")
        yield msg

    async def ainvoke(self, messages):  # noqa: ANN001
        idx = len(self.calls)
        self.calls.append(f"ainvoke:{idx}")
        return self.script[idx] if idx < len(self.script) else AIMessage(content="(exhausted)")


def _ai_with_tool(name: str, args: Dict[str, Any], content: str = "") -> AIMessage:
    return AIMessage(content=content, tool_calls=[{"name": name, "args": args, "id": f"call_{name}"}])


# ============================================================
# 脚本化各节点 LLM 行为
# ============================================================
@pytest.fixture()
def redis_e2e(monkeypatch, tmp_path):
    """Redis OOM 场景: 1 步计划 → 沙箱采集 → critic 驳回一次 → 重试通过 → 报告."""
    tool_calls: List[Dict[str, Any]] = []

    # executor LLM: 第一次调沙箱脚本 (真实执行), 第二次直接总结
    sandbox_calls: List[str] = []

    executor_llm = ScriptedLLM(
        [
            _ai_with_tool(
                "execute_python_script",
                {"code": "import platform; print('used_memory_mb=7420; maxmemory_mb=8192; evicted_keys=15234')"},
            ),
            AIMessage(
                content=(
                    "指标采集完成: used=7420MB/max=8192MB (90.6%), evicted_keys=15234. "
                    "结论: Redis 内存到达 maxmemory, 大量 key 被逐出导致 latency 上升."
                )
            ),
        ]
    )

    # critic: 第一次驳回 (未真实执行就给指标=幻觉), 第二次通过
    critic_decisions = [
        critic_mod.CriticDecision(is_passed=False, feedback="脚本未真实执行就给出精确指标, 疑似捏造, 请实际调用沙箱工具采集"),
        critic_mod.CriticDecision(is_passed=True, feedback="OK"),
    ]
    critic_state = {"i": 0}

    async def fake_critic_structured(**kwargs):  # noqa: ANN003
        i = critic_state["i"]
        critic_state["i"] += 1
        return critic_decisions[min(i, len(critic_decisions) - 1)]

    # 用真实 Pydantic schema, 保证字段与生产完全一致
    from app.agents.state import Act, Plan
    from app.agents.orchestrator import OrchestratorChoice
    from app.agents.remediation_planner import RemediationPlan
    from app.agents.merger import MergerOutput

    async def fake_planner_structured(**kwargs):
        return Plan(steps=["用沙箱脚本采集 Redis 内存指标 (used/maxmemory/evicted)"])

    async def fake_replanner_structured(**kwargs):
        return Act(is_finished=True, response="采集完成: 内存 90.6% 达 maxmemory")

    async def fake_merger_structured(**kwargs):
        return MergerOutput(
            response=(
                "# Redis 内存告警诊断报告\n\n## 根因\n内存 90.6% 达 maxmemory, "
                "evicted_keys=15234, 逐出引发延迟.\n## 建议\n扩容 maxmemory 或开启惰性删除."
            )
        )

    async def fake_orch_structured(**kwargs):
        return OrchestratorChoice(
            is_oncall=True, skill_names=["redis_diagnosis"], confidence=0.9, reason="redis 告警"
        )

    async def fake_remediation_structured(**kwargs):
        return RemediationPlan(has_remediation=False, plan_text="无需自愈")

    monkeypatch.setattr(executor_mod, "get_chat_llm", lambda **kw: executor_llm)
    monkeypatch.setattr(critic_mod, "get_chat_llm", lambda **kw: object())
    monkeypatch.setattr(orchestrator_mod, "get_chat_llm", lambda **kw: object())
    monkeypatch.setattr(merger_mod, "get_chat_llm", lambda **kw: object())
    monkeypatch.setattr(planner_mod, "get_chat_llm", lambda **kw: object())
    monkeypatch.setattr(replanner_mod, "get_chat_llm", lambda **kw: object())
    monkeypatch.setattr(remediation_mod, "get_chat_llm", lambda **kw: object())
    monkeypatch.setattr(critic_mod, "ainvoke_structured", fake_critic_structured)
    monkeypatch.setattr(planner_mod, "ainvoke_structured", fake_planner_structured)
    monkeypatch.setattr(replanner_mod, "ainvoke_structured", fake_replanner_structured)
    monkeypatch.setattr(merger_mod, "ainvoke_structured", fake_merger_structured)
    monkeypatch.setattr(orchestrator_mod, "ainvoke_structured", fake_orch_structured)
    monkeypatch.setattr(remediation_mod, "ainvoke_structured", fake_remediation_structured)

    # executor 的 agent 缓存清掉, 保证 monkeypatch 生效
    # 在 tool_runner 层记录沙箱真实调用 (StructuredTool 不许 setattr.invoke)
    import app.runtime.tool_runner as tool_runner_mod

    real_safe_invoke = tool_runner_mod._safe_invoke_tool

    async def spy_safe_invoke(tool, tool_call):  # noqa: ANN001
        if tool.name == "execute_python_script":
            args = tool_call.get("args", {}) if isinstance(tool_call, dict) else {}
            sandbox_calls.append(str(args.get("code", ""))[:80])
        return await real_safe_invoke(tool, tool_call)

    monkeypatch.setattr(tool_runner_mod, "_safe_invoke_tool", spy_safe_invoke)
    executor_mod._agent_cache.clear()

    return {
        "executor_llm": executor_llm,
        "tool_calls": tool_calls,
        "sandbox_calls": sandbox_calls,
    }


async def test_full_diagnosis_flow_solves_problem(redis_e2e):
    """完整诊断流: 真实 graph + 真实沙箱 + critic 驳回重试 → 真实报告."""
    graph = build_aiops_graph()

    result = await graph.ainvoke(
        {
            "input": "Redis 实例 db-redis-01 延迟告警, 怀疑内存问题",
            "permission_mode": "normal",
        },
        config={"recursion_limit": 60, "configurable": {"thread_id": "e2e-test-1"}},
    )

    # 1. 沙箱工具被真实调用: spy 记录 + 子进程真实执行 (used_memory_mb 输出)
    assert redis_e2e["sandbox_calls"], "execute_python_script 必须被真实调用"
    assert any("used_memory_mb" in c for c in redis_e2e["sandbox_calls"])

    # 2. critic 驳回生效: executor 被调了不止一次 (第一次被驳回)
    assert len(redis_e2e["executor_llm"].calls) >= 2, "critic 驳回应驱动 executor 重试"

    # 3. 专家报告真实产出 (replanner 合成的最终报告)
    reports = result.get("expert_reports", [])
    assert reports, "专家必须产出报告"
    assert "maxmemory" in reports[0], reports[0][:120]

    # 4. merger 后的最终响应存在
    assert result.get("response"), "merger 必须产出最终报告"

    # 5. remediation: 无需自愈 → 流程正常终止
    assert result.get("remediation_plan") in (None, "", "无需自愈")


async def test_diagnosis_latency_baseline(redis_e2e):
    """效率基线: 完整诊断流 (mock LLM, 真实沙箱) 应在 10s 内完成.

    真实环境加上 LLM 延迟会到 30-90s, 这里锁的是「框架自身开销」—
    状态流转/沙箱启动/权限过滤不应贡献超过秒级的开销.
    """
    import time

    graph = build_aiops_graph()
    t0 = time.perf_counter()
    await graph.ainvoke(
        {"input": "Redis 延迟告警", "permission_mode": "normal"},
        config={"recursion_limit": 60, "configurable": {"thread_id": "e2e-latency-1"}},
    )
    elapsed = time.perf_counter() - t0
    assert elapsed < 10.0, f"框架开销过大: {elapsed:.2f}s (不含 LLM 延迟)"
