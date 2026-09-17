"""SecOps 研判性能基线 (CI 防劣化).

与 tests/test_e2e_diagnosis.py 的 AIOps 基线同构:
  - mock LLM 边界, 锁「框架自身开销」(不含真实 LLM 延迟)
  - 额外锁 LLM 调用次数: 研判流水固定 5 节点, LLM 调用次数暴增 =
    prompt 泄漏或回环失控, 直接红给提交者看

基线数字: 2026-09-17 实测 (mock LLM), budget 留 tolerance.
"""

from __future__ import annotations

import time

import pytest

from app.security import graph as secops_graph
from app.security.state import AnalystAssessment, FactSheet, SecCriticDecision, TriageDecision


class _CallCounter:
    """计数 mock: 记录每次 ainvoke_structured 调用属于哪个节点."""

    def __init__(self):
        self.calls = 0

    async def __call__(self, *, schema_cls, **kwargs):
        self.calls += 1
        if schema_cls is TriageDecision:
            return TriageDecision(
                alert_type="brute_force", severity="HIGH",
                key_indicators=["1.2.3.4"], should_investigate=True, reason="baseline",
            )
        if schema_cls is AnalystAssessment:
            return AnalystAssessment(
                threat_assessment="base", confidence=0.9, verdict="suspicious",
            )
        if schema_cls is SecCriticDecision:
            return SecCriticDecision(is_passed=True)
        if schema_cls is FactSheet:
            return FactSheet(summary="base", verdict="suspicious", severity="HIGH")
        raise AssertionError(f"unexpected schema: {schema_cls}")


@pytest.fixture
def counting_llm(monkeypatch):
    counter = _CallCounter()
    monkeypatch.setattr("app.security.triage.ainvoke_structured", counter)
    monkeypatch.setattr("app.security.analyst.ainvoke_structured", counter)
    monkeypatch.setattr("app.security.critic.ainvoke_structured", counter)
    monkeypatch.setattr("app.security.reporter.ainvoke_structured", counter)
    # 威胁情报走网络, mock 掉 (基线只测框架)
    async def no_intel(iocs, **kwargs):
        return []
    monkeypatch.setattr(secops_graph, "enrich_iocs", no_intel)
    return counter


ALERT = "SSH brute force from 1.2.3.4 to 10.0.0.5, 37 failed logins"


async def test_secops_latency_baseline(counting_llm):
    """完整研判流 (mock LLM) 应在 5s 内完成 — 框架开销上限."""
    graph = secops_graph.build_secops_graph()
    t0 = time.perf_counter()
    result = await graph.ainvoke({"input": ALERT}, config={"recursion_limit": 30})
    elapsed = time.perf_counter() - t0
    assert result.get("fact_sheet"), "研判必须产出报告"
    assert elapsed < 5.0, f"SecOps 框架开销过大: {elapsed:.2f}s (mock LLM, 不含真实延迟)"


async def test_secops_llm_call_budget(counting_llm):
    """LLM 调用次数预算: 主路径 4 次 (triage/analyst/critic/reporter).

    超预算 = 回环失控或新增隐式调用 — 防token 劣化的硬门禁.
    """
    graph = secops_graph.build_secops_graph()
    await graph.ainvoke({"input": ALERT}, config={"recursion_limit": 30})
    assert counting_llm.calls <= 4, (
        f"LLM 调用 {counting_llm.calls} 次超预算 4 — 检查是否引入回环失控/隐式调用"
    )


async def test_secops_skip_path_zero_deep_llm(monkeypatch):
    """初筛拦截路径: 只有 triage 一次 LLM 调用, 零深查 token."""
    async def triage_only(**kwargs):
        return TriageDecision(
            alert_type="network_scan", severity="LOW",
            should_investigate=False, reason="authorized scanner",
        )

    async def fail_if_called(**kwargs):
        raise AssertionError("skip 路径不应调用深查 LLM")

    monkeypatch.setattr("app.security.triage.ainvoke_structured", triage_only)
    monkeypatch.setattr("app.security.analyst.ainvoke_structured", fail_if_called)
    monkeypatch.setattr("app.security.critic.ainvoke_structured", fail_if_called)
    monkeypatch.setattr("app.security.reporter.ainvoke_structured", fail_if_called)

    graph = secops_graph.build_secops_graph()
    result = await graph.ainvoke({"input": "noise"}, config={"recursion_limit": 30})
    assert result.get("verdict") == "benign"
    assert result.get("fact_sheet")
