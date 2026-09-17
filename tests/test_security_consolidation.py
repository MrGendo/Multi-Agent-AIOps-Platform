"""SecOps 经验沉淀/召回 (consolidation + recall) 离线单测."""

from __future__ import annotations

from app.security import consolidation as cons
from app.security import context_provider as ctx
from app.security.consolidation import ThreatPattern


class TestConsolidate:
    async def test_valid_threat_stored(self, monkeypatch):
        captured = {}

        class FakeChunk:
            def __init__(self, content, source):
                self.page_content = content
                self.metadata = {"source": source}

        def fake_split(doc, source):
            return [FakeChunk(doc, source)]

        class FakeVS:
            def add_documents(self, chunks):
                captured["chunks"] = chunks

        monkeypatch.setattr(cons, "split_markdown", fake_split)
        monkeypatch.setattr(cons, "get_vector_store", lambda: FakeVS())

        async def fake_structured(**kwargs):
            return ThreatPattern(
                is_valid_threat=True,
                title="SSH 暴力破解典型研判",
                attack_pattern="外部 IP 高频失败登录",
                indicators="源 IP + 失败次数",
                verdict_rationale="行为证据充分",
                recommended_actions="封禁 + 核查成功登录",
            )

        monkeypatch.setattr(cons, "ainvoke_structured", fake_structured)

        await cons.consolidate_triage_report("s1", "alert text", "# 报告\n内容", "malicious")
        assert "chunks" in captured
        chunk = captured["chunks"][0]
        assert chunk.metadata["session_id"] == "s1"
        assert chunk.metadata["verdict"] == "malicious"
        assert "SSH 暴力破解" in chunk.page_content

    async def test_invalid_threat_skipped(self, monkeypatch):
        stored = []

        async def fake_structured(**kwargs):
            return ThreatPattern(is_valid_threat=False, title="噪声", attack_pattern="",
                                 indicators="", verdict_rationale="", recommended_actions="")

        monkeypatch.setattr(cons, "ainvoke_structured", fake_structured)

        class FakeVS:
            def add_documents(self, chunks):
                stored.extend(chunks)

        monkeypatch.setattr(cons, "get_vector_store", lambda: FakeVS())
        await cons.consolidate_triage_report("s2", "noise", "# 初筛拦截", "benign")
        assert stored == []

    async def test_llm_failure_fail_soft(self, monkeypatch):
        async def boom(**kwargs):
            raise RuntimeError("LLM down")

        monkeypatch.setattr(cons, "ainvoke_structured", boom)
        # 不抛异常即通过
        await cons.consolidate_triage_report("s3", "x", "# 报告", "suspicious")

    async def test_empty_report_noop(self):
        await cons.consolidate_triage_report("s4", "x", "", "")


class TestRecall:
    def test_no_vector_store_returns_empty(self, monkeypatch):
        monkeypatch.setattr(ctx, "get_vector_store", None)
        assert ctx.recall_similar_patterns("SSH brute force") == ""

    def test_recall_formats_blocks(self, monkeypatch):
        class FakeDoc:
            def __init__(self, content, h1, verdict):
                self.page_content = content
                self.metadata = {"h1": h1, "verdict": verdict}

        class FakeVS:
            def similarity_search(self, q, k, expr):
                assert "secops_experience" in expr
                return [
                    FakeDoc("历史研判内容 A" * 5, "SSH 爆破研判", "malicious"),
                    FakeDoc("历史研判内容 B", "扫描噪声甄别", "benign"),
                ]

        monkeypatch.setattr(ctx, "get_vector_store", lambda: FakeVS())
        out = ctx.recall_similar_patterns("SSH brute force from 1.2.3.4")
        assert "SSH 爆破研判" in out
        assert "当时判定: malicious" in out
        assert "不得直接复用" in out  # 纪律声明在场

    def test_no_hits_returns_empty(self, monkeypatch):
        class FakeVS:
            def similarity_search(self, q, k, expr):
                return []

        monkeypatch.setattr(ctx, "get_vector_store", lambda: FakeVS())
        assert ctx.recall_similar_patterns("whatever") == ""

    def test_exception_fail_soft(self, monkeypatch):
        def boom():
            raise RuntimeError("milvus down")

        monkeypatch.setattr(ctx, "get_vector_store", boom)
        assert ctx.recall_similar_patterns("x") == ""
