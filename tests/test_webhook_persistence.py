"""webhook 持久化接线测试: 去重窗口 + diagnostic_runs 生命周期 + 禁用时降级.

离线: persistence 用 tmp sqlite; aiops_service.stream_diagnose 全程 mock.
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator, Dict, List

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

import app.api.v1.webhook as webhook_mod
import app.db.session as db_session
from app.db.models import DiagnosticRun, RunStatus
from app.db.persistence import persistence


@pytest.fixture(autouse=True)
def _fresh_db(tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path}/webhook.db"
    db_session.reset_for_tests(url)
    yield
    db_session.reset_for_tests()
    import os

    os.environ.pop("DATABASE_URL", None)


@pytest.fixture()
def fake_stream(monkeypatch):
    """mock aiops_service.stream_diagnose: 立即产出一个 report 事件."""

    async def _fake(query: str, session_id: str = "") -> AsyncIterator[Dict[str, Any]]:
        yield {"type": "skill_selected", "data": {"skill": "redis"}}
        yield {"type": "report", "data": {"report": "# 诊断报告"}}

    monkeypatch.setattr(webhook_mod.aiops_service, "stream_diagnose", _fake)
    return _fake


def _payload(fingerprint: str = "fp-a") -> Dict[str, Any]:
    return {
        "version": "4",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "HighCPUUsage",
                    "severity": "critical",
                    "instance": "db-01:9100",
                },
                "annotations": {"summary": "CPU 高"},
                "startsAt": "2026-08-27T08:00:00Z",
                "fingerprint": fingerprint,
            }
        ],
    }


# 不用 with (跳过 lifespan: 避免离线环境校验 API key / 连 Milvus).
# BackgroundTasks 在 TestClient 里响应返回前同步执行.
@pytest.fixture()
def client(fake_stream):
    from app.main import app

    return TestClient(app)


def _runs() -> List[DiagnosticRun]:
    async def _q():
        async with db_session.get_session() as sess:
            return list((await sess.execute(select(DiagnosticRun))).scalars().all())

    return asyncio.run(_q())


def _alerts():
    from app.db.models import Alert

    async def _q():
        async with db_session.get_session() as sess:
            return list((await sess.execute(select(Alert))).scalars().all())

    return asyncio.run(_q())


# ============================================================
# 集成: webhook → 告警落库 + 诊断 run 生命周期
# ============================================================
def test_webhook_persists_alert_and_run(client):
    resp = client.post("/api/v1/webhook/alertmanager", json=_payload())
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "accepted"
    assert len(body["triggered"]) == 1

    alerts = _alerts()
    assert len(alerts) == 1
    assert alerts[0].fingerprint == "fp-a"
    assert alerts[0].alertname == "HighCPUUsage"
    assert alerts[0].occurrence_count == 1

    runs = _runs()
    assert len(runs) == 1
    assert runs[0].status == RunStatus.SUCCESS
    assert runs[0].alert_id == alerts[0].id
    assert runs[0].report == "# 诊断报告"
    assert runs[0].duration_ms >= 0


def test_webhook_dedup_within_window(client):
    # 第一次: 触发诊断
    r1 = client.post("/api/v1/webhook/alertmanager", json=_payload("fp-dup"))
    assert len(r1.json()["triggered"]) == 1
    assert len(_runs()) == 1

    # 第二次同 fingerprint: 窗口内 → 去重跳过
    r2 = client.post("/api/v1/webhook/alertmanager", json=_payload("fp-dup"))
    body = r2.json()
    assert body["triggered"] == []
    assert any("dedup" in s for s in body["skipped"])

    # run 不新增; alert upsert 计数 +1
    assert len(_runs()) == 1
    alerts = _alerts()
    assert alerts[0].occurrence_count == 2


def test_webhook_disabled_persistence_still_accepts(monkeypatch, tmp_path):
    # 持久化整体禁用 → record/recently 全 no-op, 告警照常触发诊断
    async def _fake(query: str, session_id: str = ""):
        yield {"type": "report", "data": {"report": "r"}}

    monkeypatch.setattr(webhook_mod.aiops_service, "stream_diagnose", _fake)

    # 文件挡路: 路径中一段是普通文件 → mkdir 必败 → init 禁用
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file")
    db_session.reset_for_tests(f"sqlite+aiosqlite:///{blocker}/sub/x.db")
    assert asyncio.run(db_session.init_db()) is False

    from app.main import app

    c = TestClient(app)
    resp = c.post("/api/v1/webhook/alertmanager", json=_payload("fp-off"))
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["triggered"]) == 1  # 诊断照常触发 (降级不阻塞)
    assert not any("dedup" in s for s in body["skipped"])  # 去重查询也 no-op
    # 全程禁用态未被意外翻转, 所有 no-op 调用未崩溃
    assert db_session.persistence_enabled is False
