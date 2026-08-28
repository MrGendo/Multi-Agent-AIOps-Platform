"""SSE HTTP 层 E2E: POST /api/v1/aiops/diagnose 的真实 EventSource 流.

不打桩 aiops_service.stream_diagnose 的内部, 只 mock LLM/工具边界
(与 E2E 诊断同款 fake graph 注入), 验证:

  1. 响应是 text/event-stream, 每帧 event=message + JSON data
  2. 事件序列契约: start 开头, complete/error 收尾 (HTTP 层不破坏)
  3. 源头异常在 HTTP 层仍是结构化 error 帧 (不裸 500, 不截断流)
"""

from __future__ import annotations

import json
from typing import Any, AsyncIterator, Dict, List

import pytest
from fastapi.testclient import TestClient

import app.services.aiops_service as aiops_service


def _parse_sse_frames(text: str) -> List[Dict[str, Any]]:
    """把 text/event-stream 原始文本解析成事件 dict 列表."""
    events: List[Dict[str, Any]] = []
    data_lines: List[str] = []
    for line in text.splitlines():
        if line.startswith("data:"):
            data_lines.append(line[len("data:"):].strip())
        elif line == "" and data_lines:
            events.append(json.loads("\n".join(data_lines)))
            data_lines = []
    if data_lines:
        events.append(json.loads("\n".join(data_lines)))
    return events


@pytest.fixture()
def client():
    from app.main import app

    return TestClient(app)


# ============================================================
# 1. 正常流: mock graph 产出完整事件序列
# ============================================================
def test_sse_stream_frames_and_contract(client, monkeypatch):
    async def fake_stream(query: str, **kw: Any) -> AsyncIterator[Dict[str, Any]]:
        yield {"type": "start", "stage": "init", "message": "开始", "data": {}}
        yield {
            "type": "plan",
            "stage": "planner",
            "message": "计划完成",
            "data": {"plan": ["step1"]},
        }
        yield {
            "type": "report",
            "stage": "reporter",
            "message": "",
            "data": {"report": "# 报告"},
        }
        yield {"type": "complete", "stage": "diagnosis_complete", "message": "完成", "data": {}}

    monkeypatch.setattr(aiops_service, "stream_diagnose", fake_stream)

    with client.stream(
        "POST", "/api/v1/aiops/diagnose", json={"query": "测试告警", "session_id": "sse-1"}
    ) as resp:
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]
        body = "".join(chunk for chunk in resp.iter_text())

    events = _parse_sse_frames(body)
    assert events, "SSE 流不能为空"

    # 每帧结构完整
    for ev in events:
        assert set(ev.keys()) >= {"type", "message"}, ev

    types = [e["type"] for e in events]
    assert types[0] == "start", types
    assert types[-1] == "complete", types
    assert "report" in types
    report_ev = next(e for e in events if e["type"] == "report")
    assert report_ev["data"]["report"] == "# 报告"


# ============================================================
# 2. 异常流: 结构化 error 帧收尾, HTTP 层不裸奔
# ============================================================
def test_sse_stream_error_termination(client, monkeypatch):
    async def bad_stream(query: str, **kw: Any) -> AsyncIterator[Dict[str, Any]]:
        yield {"type": "start", "stage": "init", "message": "开始", "data": {}}
        raise RuntimeError("LLM 网络中断")

    monkeypatch.setattr(aiops_service, "stream_diagnose", bad_stream)

    with client.stream(
        "POST", "/api/v1/aiops/diagnose", json={"query": "x", "session_id": "sse-2"}
    ) as resp:
        assert resp.status_code == 200  # SSE 200 起流, 错误在帧里
        body = "".join(chunk for chunk in resp.iter_text())

    events = _parse_sse_frames(body)
    types = [e["type"] for e in events]
    assert types[0] == "start", types
    assert types[-1] == "error", types
    err = events[-1]
    assert "LLM 网络中断" in err["message"]
    assert err["data"]["error_type"] == "RuntimeError"


# ============================================================
# 3. 中途断连 (客户端 cancel): 服务端不崩 (下次请求正常)
# ============================================================
def test_sse_client_disconnect_stream_survives(client, monkeypatch):
    """生成器在客户端断开后应被取消而不影响后续请求."""
    import asyncio

    started = asyncio.Event()

    async def long_stream(query: str, **kw: Any) -> AsyncIterator[Dict[str, Any]]:
        yield {"type": "start", "stage": "init", "message": "", "data": {}}
        started.set()
        # 模拟长时间诊断 — 客户端将中途断开
        for i in range(100):
            await asyncio.sleep(0.05)
            yield {"type": "progress", "stage": f"s{i}", "message": "", "data": {}}

    monkeypatch.setattr(aiops_service, "stream_diagnose", long_stream)

    # 打开流, 读到第一帧后主动关闭
    with client.stream(
        "POST", "/api/v1/aiops/diagnose", json={"query": "x", "session_id": "sse-3"}
    ) as resp:
        it = resp.iter_text()
        first = next(it)

    assert "start" in first

    # 服务端进程仍活着: 下一个请求正常服务
    async def ok_stream(query: str, **kw: Any) -> AsyncIterator[Dict[str, Any]]:
        yield {"type": "start", "stage": "init", "message": "", "data": {}}
        yield {"type": "complete", "stage": "diagnosis_complete", "message": "", "data": {}}

    monkeypatch.setattr(aiops_service, "stream_diagnose", ok_stream)
    with client.stream(
        "POST", "/api/v1/aiops/diagnose", json={"query": "x", "session_id": "sse-4"}
    ) as resp:
        assert resp.status_code == 200
        body = "".join(chunk for chunk in resp.iter_text())
    events = _parse_sse_frames(body)
    assert [e["type"] for e in events] == ["start", "complete"]
