"""Precheck (目标存在性预检门) 测试.

全部离线: 探测经 _probe_port 包装函数 monkeypatch (StructuredTool 不可 patch).
"""

import pytest

from app.agents import precheck as pc
from app.agents.precheck import (
    _extract_local_candidates,
    precheck_enabled,
    precheck_node,
    run_precheck,
)


# ---------- 目标提取 ----------

def test_extract_readme_case_mysql():
    q = "线上订单服务大面积超时，请网络专家和数据库专家同时排查：网络连通性和MySQL慢查询都要查"
    assert _extract_local_candidates(q) == ["127.0.0.1:3306"]


def test_extract_explicit_local_hostport():
    assert _extract_local_candidates("127.0.0.1:6379 连不上") == ["127.0.0.1:6379"]
    assert _extract_local_candidates("localhost:5432 拒绝连接") == ["127.0.0.1:5432"]


def test_extract_remote_not_local():
    # 远端 IP/域名一律不进本机候选 (放行语义)
    assert _extract_local_candidates("10.0.0.5:3306 的 MySQL 连不上") == []
    assert _extract_local_candidates("api.example.com 超时") == []


def test_extract_no_target():
    assert _extract_local_candidates("我的电脑很卡") == []
    assert _extract_local_candidates("系统负载高，帮忙看看") == []


def test_extract_local_context_service():
    assert _extract_local_candidates("本机 redis 连接超时") == ["127.0.0.1:6379"]


def test_extract_explicit_port():
    assert "127.0.0.1:9200" in _extract_local_candidates("端口 9200 没有监听")


# ---------- 判定三态 ----------

async def test_refuted_when_refused_twice(monkeypatch):
    async def fake_probe(host, port):
        return "Connection refused (127.0.0.1:3306): 无监听"
    monkeypatch.setattr(pc, "_probe_port", fake_probe)
    v = await run_precheck("MySQL 3306 连不上")
    assert v.status == "refuted"
    assert v.targets and v.targets[0].spec == "127.0.0.1:3306"
    assert "不存在" in v.report and "3306" in v.report


async def test_verified_when_port_open(monkeypatch):
    async def fake_probe(host, port):
        return "Port 3306 is open"
    monkeypatch.setattr(pc, "_probe_port", fake_probe)
    v = await run_precheck("MySQL 3306 连不上")
    assert v.status == "verified"
    assert v.report == ""


async def test_unverifiable_on_timeout(monkeypatch):
    async def fake_probe(host, port):
        return "Connection timed out after 3s"  # timeout ≠ refused, 放行
    monkeypatch.setattr(pc, "_probe_port", fake_probe)
    v = await run_precheck("MySQL 3306 连不上")
    assert v.status == "unverifiable"


async def test_unverifiable_when_tool_broken(monkeypatch):
    async def fake_probe(host, port):
        raise RuntimeError("mcp down")
    monkeypatch.setattr(pc, "_probe_port", fake_probe)
    v = await run_precheck("MySQL 3306 连不上")
    assert v.status == "unverifiable"


async def test_unverifiable_when_no_target():
    v = await run_precheck("系统好卡")
    assert v.status == "unverifiable"


async def test_refuted_requires_both_refused(monkeypatch):
    """一次 refused 一次 open → 不能证伪 (目标活着, 放行)."""
    calls = {"n": 0}

    async def fake_probe(host, port):
        calls["n"] += 1
        return "Connection refused" if calls["n"] == 1 else "Port open"
    monkeypatch.setattr(pc, "_probe_port", fake_probe)
    v = await run_precheck("MySQL 3306 连不上")
    assert v.status == "verified"


# ---------- env 开关 ----------

async def test_env_switch_off(monkeypatch):
    monkeypatch.setenv("AIOPS_PRECHECK_ENABLED", "false")
    assert precheck_enabled() is False
    out = await precheck_node({"input": "MySQL 3306 连不上"})
    assert out["precheck_status"] == "unverifiable"
    assert "response" not in out  # 不短路


# ---------- 节点行为 ----------

async def test_node_refuted_short_circuits(monkeypatch):
    async def fake_probe(host, port):
        return "Connection refused x (no listener)"
    monkeypatch.setattr(pc, "_probe_port", fake_probe)
    out = await precheck_node({"input": "MySQL 3306 连不上"})
    assert out["precheck_status"] == "refuted"
    assert "不存在" in out["response"]
    # transition 记录可观测
    reasons = [t.get("reason") for t in out.get("transition_history", [])]
    assert any("precheck_target_refuted" in r for r in reasons)


async def test_node_passes_through_when_unverifiable(monkeypatch):
    async def fake_probe(host, port):
        return "timeout"
    monkeypatch.setattr(pc, "_probe_port", fake_probe)
    out = await precheck_node({"input": "MySQL 3306 连不上"})
    assert out["precheck_status"] == "unverifiable"
    assert "response" not in out


# ---------- 图级: refuted 时不进专家 ----------

async def test_graph_short_circuits_before_experts(monkeypatch):
    """端到端: 本机 mysql 被证伪 → 图在 precheck 后终止, 不进 orchestrator/expert."""
    from app.agents.graph import build_aiops_graph

    async def fake_probe(host, port):
        return "Connection refused (RST, no listener)"
    monkeypatch.setattr(pc, "_probe_port", fake_probe)

    # 用图级 checkpointer 跑, 断言 response 已填且 expert_reports 为空
    graph = build_aiops_graph()
    result = await graph.ainvoke(
        {"input": "MySQL 3306 连不上", "permission_mode": "normal"},
        config={"recursion_limit": 30, "configurable": {"thread_id": "precheck-e2e"}},
    )
    assert result.get("precheck_status") == "refuted"
    assert "不存在" in result.get("response", "")
    assert not result.get("expert_reports"), "短路时不应有任何专家报告"
