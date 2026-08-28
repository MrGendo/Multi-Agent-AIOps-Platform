"""SSE 诊断流契约测试: stream_diagnose 事件序列的结构不变量.

契约 (前端依赖, 破坏即事故):
  1. 每个事件有 type/stage/message/data 四键
  2. 首事件 type=start
  3. 末事件 type=complete 或 error — 不允许流静默断掉
  4. report 事件只出现一次 (在 complete 之前)
  5. 源头异常必须转成 error 事件, 不允许裸异常逃逸

离线: graph/LLM 全 mock.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Dict, List

import pytest

import app.services.aiops_service as aiops_service


def _evt(event_type: str, stage: str = "", message: str = "", **data: Any) -> Dict[str, Any]:
    return {"type": event_type, "stage": stage, "message": message, "data": data}


class _FakeGraph:
    """吐固定事件序列的假 graph (astream 协议)."""

    def __init__(self, node_events: List[Dict[str, Any]]):
        self._events = node_events

    async def astream(self, *args: Any, **kwargs: Any) -> AsyncIterator[Dict[str, Any]]:
        for ev in self._events:
            yield ev


async def _collect(gen: AsyncIterator[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [e async for e in gen]


@pytest.fixture()
def reset_graph_cache():
    """每个测试重置模块级 graph 缓存."""
    aiops_service._graph = None
    yield
    aiops_service._graph = None


# ============================================================
# 契约 1: 事件四键结构
# ============================================================
async def test_event_shape_contract(reset_graph_cache):
    aiops_service._graph = _FakeGraph(
        [
            {"planner": {"plan": ["step1", "step2"]}},
            {"executor": {"past_steps": [("step1", "ok")], "current_step": "step1"}},
            {"reporter": {"final_report": "# R"}},
        ]
    )
    events = await _collect(aiops_service.stream_diagnose("q", session_id="t1"))

    assert events, "事件流不能为空"
    for ev in events:
        assert set(ev.keys()) == {"type", "stage", "message", "data"}, ev
        assert isinstance(ev["type"], str) and ev["type"], ev
        assert isinstance(ev["data"], dict), ev


# ============================================================
# 契约 2/3: start 开头, complete/error 收尾
# ============================================================
async def test_stream_starts_and_completes(reset_graph_cache):
    aiops_service._graph = _FakeGraph(
        [
            {"planner": {"plan": ["s1"]}},
            {"reporter": {"final_report": "# R"}},
        ]
    )
    events = await _collect(aiops_service.stream_diagnose("q", session_id="t2"))
    types = [e["type"] for e in events]

    assert types[0] == "start", types
    assert types[-1] in ("complete", "error"), types
    assert types[-1] == "complete"  # 正常路径必须是 complete


# ============================================================
# 契约 5: 源头异常 → error 事件收尾 (不允许裸异常)
# ============================================================
async def test_graph_exception_becomes_error_event(reset_graph_cache):
    class _Boom:
        async def astream(self, *a: Any, **k: Any) -> AsyncIterator[Dict[str, Any]]:
            yield {"planner": {"plan": ["s1"]}}
            raise RuntimeError("graph exploded")

    aiops_service._graph = _Boom()
    events = await _collect(aiops_service.stream_diagnose("q", session_id="t3"))
    types = [e["type"] for e in events]

    assert "error" in types, types
    err = [e for e in events if e["type"] == "error"][-1]
    assert "graph exploded" in err["message"]
    assert types[-1] == "error"


# ============================================================
# 并发满: 拒绝但结构完整
# ============================================================
async def test_concurrency_limit_rejected_gracefully(reset_graph_cache, monkeypatch):
    # 占满信号量
    n = aiops_service._agent_semaphore._value if hasattr(
        aiops_service._agent_semaphore, "_value"
    ) else 2
    for _ in range(max(1, n)):
        await aiops_service._agent_semaphore.acquire()

    try:
        events = await _collect(aiops_service.stream_diagnose("q", session_id="t4"))
        types = [e["type"] for e in events]
        assert types[-1] in ("complete", "error"), types
        # 应该有一个非正常结束的标志 (error 或并发提示)
        assert "error" in types or any("并发" in (e["message"] or "") for e in events)
    finally:
        for _ in range(max(1, n)):
            aiops_service._agent_semaphore.release()
