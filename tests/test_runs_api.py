"""读取路径 API 测试: /runs + /alerts (写入→读回往返).

用真实 SQLite + persistence 直写数据, 经 HTTP 读回验证:
  - run 列表分页/过滤/排序
  - run 详情含工具明细与 HITL 审计
  - alert 聚合列表 + fingerprint 关联 runs
  - 持久化禁用时 degraded 响应 (非 500)
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

import app.db.session as db_session
from app.db.persistence import persistence


@pytest.fixture(autouse=True)
def _fresh_db(tmp_path):
    db_session.reset_for_tests(f"sqlite+aiosqlite:///{tmp_path}/read.db")
    yield
    db_session.reset_for_tests()
    import os

    os.environ.pop("DATABASE_URL", None)


@pytest.fixture()
def client():
    from app.main import app

    return TestClient(app)


@pytest.fixture()
def _seed():
    """写入: 2 告警, 3 runs (含 1 失败), 工具明细, HITL 审计."""

    async def _do():
        assert await db_session.init_db()
        aid1 = await persistence.record_alert(
            fingerprint="fp-highcpu", alertname="HighCPU", severity="critical", instance="node-1"
        )
        aid2 = await persistence.record_alert(
            fingerprint="fp-disk", alertname="DiskFull", severity="warning", instance="node-2"
        )
        # fp-highcpu 再来一次 → occurrence_count=2
        await persistence.record_alert(fingerprint="fp-highcpu", alertname="HighCPU")

        r1 = await persistence.start_run(query="CPU 告警诊断", session_id="s1", alert_id=aid1)
        await persistence.log_tool_exec(
            r1, tool_name="get_local_cpu_memory", result={"cpu": 98.5}, elapsed_ms=30
        )
        await persistence.log_tool_exec(
            r1, tool_name="execute_python_script", result="ok", status="failed", elapsed_ms=120
        )
        await persistence.record_hitl(r1, action="approve", approved=True, approver="ops")
        await persistence.finish_run(
            r1, "SUCCESS", report="# r", total_tokens=1200, tool_calls=2, duration_ms=4500
        )

        r2 = await persistence.start_run(query="CPU 又告警", session_id="s2", alert_id=aid1)
        await persistence.finish_run(r2, "FAILED", error="LLMError: timeout", duration_ms=900)

        r3 = await persistence.start_run(query="磁盘告警诊断", session_id="s3", alert_id=aid2)
        await persistence.finish_run(r3, "SUCCESS", total_tokens=800, duration_ms=3000)
        return aid1

    return asyncio.run(_do())


def test_runs_list_pagination_and_filter(client, _seed):
    resp = client.get("/api/v1/runs", params={"page": 1, "page_size": 2})
    assert resp.status_code == 200
    body = resp.json()["data"]
    assert body["total"] == 3
    assert len(body["items"]) == 2
    assert body["degraded"] is False
    # 时间倒序: 最新在前
    assert body["items"][0]["query"] == "磁盘告警诊断"

    # 状态过滤
    resp2 = client.get("/api/v1/runs", params={"status": "FAILED"})
    items = resp2.json()["data"]["items"]
    assert len(items) == 1
    assert items[0]["status"] == "FAILED"
    assert "timeout" in items[0]["error"]


def test_run_detail_with_tools_and_hitl(client, _seed):
    async def _first_run_id():
        from sqlalchemy import select

        from app.db.models import DiagnosticRun

        async with db_session.get_session() as sess:
            row = (
                await sess.execute(
                    select(DiagnosticRun).where(DiagnosticRun.session_id == "s1")
                )
            ).scalar_one()
            return row.id

    run_id = asyncio.run(_first_run_id())

    resp = client.get(f"/api/v1/runs/{run_id}")
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["run"]["status"] == "SUCCESS"
    assert data["run"]["total_tokens"] == 1200
    assert data["run"]["tool_calls"] == 2

    assert len(data["tool_executions"]) == 2
    failed = [t for t in data["tool_executions"] if t["status"] == "failed"]
    assert failed and failed[0]["tool_name"] == "execute_python_script"

    assert len(data["hitl_audit"]) == 1
    assert data["hitl_audit"][0]["approved"] is True


def test_run_not_found(client, _seed):
    resp = client.get("/api/v1/runs/no-such-id")
    body = resp.json()
    assert body["code"] == "NOT_FOUND"


def test_alerts_list_and_detail(client, _seed):
    resp = client.get("/api/v1/alerts")
    items = resp.json()["data"]["items"]
    assert resp.json()["data"]["total"] == 2
    by_fp = {a["fingerprint"]: a for a in items}
    assert by_fp["fp-highcpu"]["occurrence_count"] == 2  # upsert 生效
    assert by_fp["fp-disk"]["severity"] == "warning"

    # fingerprint 详情 → 关联 runs (fp-highcpu 有 2 条)
    resp2 = client.get("/api/v1/alerts/fp-highcpu")
    data = resp2.json()["data"]
    assert data["alert"]["alertname"] == "HighCPU"
    assert len(data["runs"]) == 2


def test_degraded_when_persistence_disabled(client):
    # 不 init → 持久化禁用 → degraded 响应而非 500
    assert db_session.persistence_enabled is False
    resp = client.get("/api/v1/runs")
    body = resp.json()
    assert resp.status_code == 200
    assert body["code"] == "DEGRADED"
    assert body["data"]["degraded"] is True

    resp2 = client.get("/api/v1/alerts")
    assert resp2.json()["code"] == "DEGRADED"
