"""经验回流链路测试: consolidate_diagnosis_report (Consolidation Worker).

「越用越聪明」闭环的三条分支 + 静默吞异常红线:
  1. 有效故障 → 提炼 + 切分 + 入库 (source=experience_db, 带元数据)
  2. 非故障 (is_valid_incident=False) → 不入库
  3. LLM 提炼失败 → 静默返回 (fire-and-forget 不抛)
  4. 入库失败 (Milvus 挂) → 静默返回, 不影响主流程
  5. 空报告 → 直接返回不调 LLM
"""

from __future__ import annotations

from typing import List

import pytest

import app.services.consolidation_worker as cw
from app.services.consolidation_worker import ExperiencePattern, consolidate_diagnosis_report


@pytest.fixture(autouse=True)
def _no_llm(monkeypatch):
    monkeypatch.setattr(cw, "get_chat_llm", lambda **kw: object())


def _pattern(is_valid: bool = True) -> ExperiencePattern:
    return ExperiencePattern(
        is_valid_incident=is_valid,
        title="Redis OOM 导致接口超时",
        symptoms="接口 p99 超时, Redis 延迟上升",
        root_cause="maxmemory 到顶, evicted_keys 激增",
        remediation="扩容 maxmemory + 开启惰性删除",
    )


async def test_valid_incident_ingested_with_metadata(monkeypatch):
    added: List = []
    calls: List[str] = []

    async def fake_structured(**kw):
        calls.append("llm")
        return _pattern()

    class FakeVS:
        def add_documents(self, chunks):  # noqa: ANN101
            added.extend(chunks)

    monkeypatch.setattr(cw, "ainvoke_structured", fake_structured)
    monkeypatch.setattr(cw, "get_vector_store", lambda: FakeVS())

    await consolidate_diagnosis_report("sess-1", "Redis 超时告警", "# 报告\n根因: 内存到顶")

    assert calls == ["llm"]
    assert added, "有效故障必须入库"
    for c in added:
        assert c.metadata["source"] == "experience_db"
        assert c.metadata["session_id"] == "sess-1"
        assert c.metadata["type"] == "historical_experience"
    # 内容含提炼后的三段结构
    full = "\n".join(c.page_content for c in added)
    assert "故障现象" in full or "根因分析" in full


async def test_not_incident_skips_ingestion(monkeypatch):
    added: List = []

    async def fake_structured(**kw):
        return _pattern(is_valid=False)

    class FakeVS:
        def add_documents(self, chunks):  # noqa: ANN101
            added.extend(chunks)

    monkeypatch.setattr(cw, "ainvoke_structured", fake_structured)
    monkeypatch.setattr(cw, "get_vector_store", lambda: FakeVS())

    await consolidate_diagnosis_report("s", "闲聊咨询", "# 问答")
    assert added == [], "非故障不得入库"


async def test_llm_failure_swallowed(monkeypatch):
    async def boom(**kw):
        raise RuntimeError("LLM down")

    monkeypatch.setattr(cw, "ainvoke_structured", boom)
    monkeypatch.setattr(cw, "get_vector_store", lambda: pytest.fail("不应触达向量库"))

    # fire-and-forget 红线: 不抛
    await consolidate_diagnosis_report("s", "q", "# r")


async def test_vector_store_failure_swallowed(monkeypatch):
    async def fake_structured(**kw):
        return _pattern()

    class DeadVS:
        def add_documents(self, chunks):  # noqa: ANN101
            raise ConnectionError("Milvus down")

    monkeypatch.setattr(cw, "ainvoke_structured", fake_structured)
    monkeypatch.setattr(cw, "get_vector_store", lambda: DeadVS())

    await consolidate_diagnosis_report("s", "q", "# r")  # 不抛


async def test_empty_report_returns_early(monkeypatch):
    monkeypatch.setattr(
        cw, "ainvoke_structured", lambda **kw: pytest.fail("空报告不应调 LLM")
    )
    await consolidate_diagnosis_report("s", "q", "")
