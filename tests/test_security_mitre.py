"""MITRE 知识库检索 (recall_mitre_details) 离线单测."""

from __future__ import annotations

from app.security import context_provider as ctx


class TestRecallMitre:
    def test_empty_ids_returns_empty(self):
        assert ctx.recall_mitre_details([]) == ""

    def test_no_vector_store_returns_empty(self, monkeypatch):
        monkeypatch.setattr(ctx, "get_vector_store", None)
        assert ctx.recall_mitre_details(["T1110"]) == ""

    def test_recall_by_tid_expr(self, monkeypatch):
        class FakeDoc:
            def __init__(self, chapter, content):
                self.page_content = content
                self.metadata = {"source": "mitre_attack", "chapter": chapter}

        class FakeVS:
            def similarity_search(self, q, k, expr=None):
                assert "mitre_attack" in (expr or "")
                return [
                    FakeDoc("T1110 Brute Force", "# T1110 Brute Force\n## 检测建议\nMonitor authentication logs"),
                    FakeDoc("T9999 Other", "# T9999 Other\ncontent"),  # 混入其他技术, 应被过滤
                ]

        monkeypatch.setattr(ctx, "get_vector_store", lambda: FakeVS())
        out = ctx.recall_mitre_details(["T1110"])
        assert "Brute Force" in out
        assert "检测建议" in out
        assert "T9999" not in out  # 客户端按 chapter 前缀 "T1110 " 过滤

    def test_cap_six_techniques(self, monkeypatch):
        seen = []

        class FakeVS:
            def similarity_search(self, q, k, expr=None):
                seen.append(q)
                return []

        monkeypatch.setattr(ctx, "get_vector_store", lambda: FakeVS())
        ctx.recall_mitre_details([f"T1{i:03d}" for i in range(10)])
        assert len(seen) == 6

    def test_exception_fail_soft(self, monkeypatch):
        def boom():
            raise RuntimeError("milvus down")

        monkeypatch.setattr(ctx, "get_vector_store", boom)
        assert ctx.recall_mitre_details(["T1110"]) == ""
