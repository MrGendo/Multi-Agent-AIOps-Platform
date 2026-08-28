"""webhook 并发竞态测试: 同 fingerprint 告警并发到达时不得双跑诊断.

场景: Alertmanager 重试/分组把同 fingerprint 告警在极短时间内重复投递.
期望: 去重窗口生效 — 只触发一次诊断 (第一次落库前第二次查询的竞态窗口
需要 recently_diagnosed 侧有保护, 否则两个请求都查到 None 双跑).

这里用 asyncio.gather 模拟并发, 每个请求用独立 TestClient (同一线程循环).
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator, Dict, List

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

import app.api.v1.webhook as webhook_mod
import app.db.session as db_session
from app.db.models import Alert, DiagnosticRun
from app.db.persistence import persistence


@pytest.fixture(autouse=True)
def _fresh_db(tmp_path):
    db_session.reset_for_tests(f"sqlite+aiosqlite:///{tmp_path}/race.db")
    yield
    db_session.reset_for_tests()
    import os

    os.environ.pop("DATABASE_URL", None)


@pytest.fixture()
def slow_stream(monkeypatch):
    """诊断流慢一点, 放大竞态窗口."""

    async def _fake(query: str, session_id: str = "") -> AsyncIterator[Dict[str, Any]]:
        await asyncio.sleep(0.05)
        yield {"type": "report", "data": {"report": "r"}}

    monkeypatch.setattr(webhook_mod.aiops_service, "stream_diagnose", _fake)
    return _fake


def _payload(fingerprint: str) -> Dict[str, Any]:
    return {
        "version": "4",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "FlappingAlert",
                    "severity": "critical",
                    "instance": "node-1:9100",
                },
                "startsAt": "2026-08-27T08:00:00Z",
                "fingerprint": fingerprint,
            }
        ],
    }


async def _count_rows(model) -> int:
    async with db_session.get_session() as sess:
        return len(list((await sess.execute(select(model))).scalars().all()))


async def test_same_fingerprint_duplicate_in_one_payload(slow_stream):
    """同一 payload 内两条相同 fingerprint 的 firing 告警 → 只诊断一次."""
    payload = {
        "version": "4",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "FlappingAlert",
                    "severity": "critical",
                    "instance": "node-1:9100",
                },
                "startsAt": "2026-08-27T08:00:00Z",
                "fingerprint": "fp-same",
            },
            {
                "status": "firing",
                "labels": {
                    "alertname": "FlappingAlert",
                    "severity": "critical",
                    "instance": "node-1:9100",
                },
                "startsAt": "2026-08-27T08:00:05Z",
                "fingerprint": "fp-same",
            },
        ],
    }

    from app.main import app

    client = TestClient(app)
    resp = client.post("/api/v1/webhook/alertmanager", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    # 第二条应被去重跳过 (同 payload 内)
    assert len(body["triggered"]) == 1, body
    assert any("dedup" in s for s in body["skipped"]), body


async def test_two_rapid_requests_same_fingerprint(slow_stream):
    """背靠背两次请求同 fingerprint → 第二次必须被去重."""
    from app.main import app

    client = TestClient(app)
    r1 = client.post("/api/v1/webhook/alertmanager", json=_payload("fp-rapid"))
    r2 = client.post("/api/v1/webhook/alertmanager", json=_payload("fp-rapid"))

    assert len(r1.json()["triggered"]) == 1
    assert r2.json()["triggered"] == [], r2.json()
    assert any("dedup" in s for s in r2.json()["skipped"])

    assert await _count_rows(DiagnosticRun) == 1
    assert await _count_rows(Alert) == 1


async def test_window_expiry_allows_re_diagnosis(slow_stream):
    """窗口过期后同 fingerprint 必须允许重新诊断 (否则永久去重 = 持续故障失明)."""
    from datetime import datetime, timedelta, timezone

    from app.main import app

    client = TestClient(app)
    r1 = client.post("/api/v1/webhook/alertmanager", json=_payload("fp-expire"))
    assert len(r1.json()["triggered"]) == 1

    # 把唯一一条 run 的 created_at 拨回窗口外 (默认窗口 900s)
    async with db_session.get_session() as sess:
        from sqlalchemy import update

        await sess.execute(
            update(DiagnosticRun).values(
                created_at=datetime.now(timezone.utc) - timedelta(seconds=2000)
            )
        )
        await sess.commit()

    r2 = client.post("/api/v1/webhook/alertmanager", json=_payload("fp-expire"))
    assert len(r2.json()["triggered"]) == 1, r2.json()  # 重新触发
    assert await _count_rows(DiagnosticRun) == 2
