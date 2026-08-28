"""性能回归基线: E2E 诊断各阶段耗时落盘 + 与基线对比.

用法:
  # 生成/刷新基线 (本地或首次):
  python scripts/perf_baseline.py update

  # 对比 (CI / 日常):
  python scripts/perf_baseline.py check

设计:
  - 度量点与 test_e2e_diagnosis 同构 (mock LLM 边界, 其余真实),
    锁定的是框架自身开销, 与 LLM 延迟无关
  - 基线含 20% 容差 (CI runner 与本机性能差异)
  - check 失败退出码 1, 可直接挂进 CI
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

BASELINE_FILE = ROOT / "tests" / "perf_baseline.json"
TOLERANCE = 1.20  # 基线 × 1.2 才算劣化

# 各阶段预算 (秒): 超出即劣化 (不含 LLM)
BUDGETS = {
    "full_diagnosis_flow": 10.0,
    "fanout_two_experts": 10.0,
    "hitl_roundtrip": 10.0,
}


def _measure_full_flow() -> float:
    import asyncio

    return asyncio.run(_run_full_flow_once())


async def _run_full_flow_once() -> float:
    # 与 tests/test_e2e_diagnosis.py 同构的 mock 注入 (最小化版)
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

    class _Noop:
        def bind_tools(self, tools):
            return self

        async def astream(self, messages):
            yield AIMessage(content="指标已采集")

        async def ainvoke(self, messages):
            return AIMessage(content="指标已采集")

    noop = _Noop()

    async def fake_critic(**kw):
        return critic_mod.CriticDecision(is_passed=True, feedback="OK")

    async def fake_planner(**kw):
        return Plan(steps=["采集指标"])

    async def fake_replanner(**kw):
        return Act(is_finished=True, response="采集完成")

    async def fake_merger(**kw):
        return MergerOutput(response="# 报告")

    async def fake_orch(**kw):
        return OrchestratorChoice(
            is_oncall=True, skill_names=["generic_oncall"], confidence=0.9, reason="r"
        )

    async def fake_remediation(**kw):
        return RemediationPlan(has_remediation=False, plan_text="无需自愈")

    import unittest.mock as mock

    with mock.patch.object(critic_mod, "get_chat_llm", lambda **kw: noop), \
         mock.patch.object(critic_mod, "ainvoke_structured", fake_critic), \
         mock.patch.object(planner_mod, "ainvoke_structured", fake_planner), \
         mock.patch.object(planner_mod, "get_chat_llm", lambda **kw: noop), \
         mock.patch.object(replanner_mod, "ainvoke_structured", fake_replanner), \
         mock.patch.object(replanner_mod, "get_chat_llm", lambda **kw: noop), \
         mock.patch.object(merger_mod, "ainvoke_structured", fake_merger), \
         mock.patch.object(merger_mod, "get_chat_llm", lambda **kw: noop), \
         mock.patch.object(orchestrator_mod, "ainvoke_structured", fake_orch), \
         mock.patch.object(orchestrator_mod, "get_chat_llm", lambda **kw: noop), \
         mock.patch.object(remediation_mod, "ainvoke_structured", fake_remediation), \
         mock.patch.object(remediation_mod, "get_chat_llm", lambda **kw: noop), \
         mock.patch.object(executor_mod, "get_chat_llm", lambda **kw: noop):
        executor_mod._agent_cache.clear()
        graph = build_aiops_graph()
        t0 = time.perf_counter()
        await graph.ainvoke(
            {"input": "性能基线测试", "permission_mode": "normal"},
            config={"recursion_limit": 60, "configurable": {"thread_id": "perf"}},
        )
        return time.perf_counter() - t0


def cmd_update() -> int:
    elapsed = _measure_full_flow()
    data = {
        "full_diagnosis_flow_sec": round(elapsed, 3),
        "budgets": BUDGETS,
        "tolerance": TOLERANCE,
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "note": "mock LLM 边界, 框架自身开销; 重新生成请在本机执行 update",
    }
    BASELINE_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2))
    print(f"基线已写入 {BASELINE_FILE}: full_flow={elapsed:.3f}s")
    return 0


def cmd_check() -> int:
    if not BASELINE_FILE.exists():
        print("SKIP: 基线文件不存在 (先运行 scripts/perf_baseline.py update)")
        return 0
    base = json.loads(BASELINE_FILE.read_text())
    baseline = float(base["full_diagnosis_flow_sec"])
    budget = float(base.get("budgets", {}).get("full_diagnosis_flow", 10.0))
    tol = float(base.get("tolerance", TOLERANCE))

    elapsed = _measure_full_flow()
    print(f"本次: {elapsed:.3f}s | 基线: {baseline:.3f}s | 预算: {budget}s | 容差: ×{tol}")

    ok = True
    if elapsed > budget:
        print(f"REGRESSION: 超出绝对预算 {budget}s")
        ok = False
    if baseline > 0 and elapsed > baseline * tol:
        print(f"REGRESSION: 超出基线×容差 ({baseline * tol:.3f}s)")
        ok = False
    if ok:
        print("PASS: 性能在基线容差内")
    return 0 if ok else 1


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    raise SystemExit(cmd_update() if cmd == "update" else cmd_check())
