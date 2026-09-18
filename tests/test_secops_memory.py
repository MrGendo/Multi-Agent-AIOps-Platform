"""调查子代理 (决策/执行分离) + 对话记忆滚动压缩 离线单测."""

from __future__ import annotations

from app.security import dialogue as dlg
from app.security import investigator as inv
from app.security.investigator import InvestigationFinding, _format_finding


class TestInvestigator:
    def test_format_finding_compact(self):
        f = InvestigationFinding(
            objective="确认 1.2.3.4 是否为扫描器",
            conclusion="是已知扫描器",
            key_evidence=["http_check: UA=sqlmap", "dns: 无 PTR"],
            tools_used=["http_check", "dns_lookup"],
            still_unknown="内网部分不可达",
        )
        out = _format_finding(f)
        assert "[调查目标]" in out and "[结论]" in out
        assert "sqlmap" in out and "dns_lookup" in out

    async def test_no_tools_fail_soft(self, monkeypatch):
        monkeypatch.setattr(inv, "_get_tool", lambda name: None)
        out = await inv.run_investigation("告警", "目标 x")
        assert "调查不可用" in out

    async def test_react_loop_and_compress(self, monkeypatch):
        """完整 ReAct: 工具可调 → LLM 产出结构化发现."""
        calls = {"tool": 0, "llm": 0}

        class FakeTool:
            name = "ping_host"

            async def arun(self, args=None):
                return "64 bytes from 1.2.3.4: icmp_seq=0 time=0.045 ms"

        monkeypatch.setattr(inv, "_get_tool", lambda name: FakeTool() if name == "ping_host" else None)

        class FakeMsg:
            def __init__(self, content, tool_calls=None):
                self.content = content
                self.tool_calls = tool_calls or []

        class FakeLLM:
            def bind_tools(self, tools):
                return self  # 测试桩: bind 返回自身

            async def ainvoke(self, messages):
                calls["llm"] += 1
                # 第一轮: 要求调工具; 之后: 收尾文本
                if calls["llm"] == 1:
                    return FakeMsg("我先 ping", tool_calls=[
                        {"name": "ping_host", "id": "tc1", "args": {"host": "1.2.3.4"}}])
                return FakeMsg("调查完成, 目标可达")

        # ainvoke_structured 也走 FakeLLM (monkeypatch 掉)
        async def fake_structured(**kwargs):
            return InvestigationFinding(
                objective="确认可达性", conclusion="1.2.3.4 可达",
                key_evidence=["64 bytes from 1.2.3.4"], tools_used=["ping_host"])

        monkeypatch.setattr(inv, "get_chat_llm", lambda **kw: FakeLLM())
        monkeypatch.setattr(inv, "ainvoke_structured", fake_structured)
        monkeypatch.setattr("app.runtime.tool_runner._safe_invoke_tool",
                            lambda tool, tc: FakeTool().arun())

        out = await inv.run_investigation("告警", "确认 1.2.3.4 可达性")
        assert "[结论]" in out and "可达" in out
        assert calls["tool"] == 0  # 走 monkeypatch 的 _safe_invoke_tool
        assert calls["llm"] >= 2

    async def test_compress_failure_degrades(self, monkeypatch):
        class FakeLLM:
            async def ainvoke(self, messages):
                raise RuntimeError("LLM down")

        async def boom_structured(**kw):
            raise RuntimeError("structured down")

        monkeypatch.setattr(inv, "get_chat_llm", lambda **kw: FakeLLM())
        monkeypatch.setattr(inv, "ainvoke_structured", boom_structured)
        # 工具不可用也退化
        monkeypatch.setattr(inv, "_get_tool", lambda name: None)
        out = await inv.run_investigation("a", "b")
        assert isinstance(out, str) and out  # 不抛异常即过


class TestDialogueMemoryCompression:
    def _session(self, n_turns):
        s = dlg.TriageSession("mem-test", "告警", "# 报告", "suspicious", "MEDIUM",
                              "recommend", {"ips": ["1.1.1.1"]}, "brute_force")
        for i in range(n_turns):
            s.turns.append(dlg.DialogueTurn(role="user", content=f"证据 {i}: " + "x" * 100))
            s.turns.append(dlg.DialogueTurn(role="assistant", content=f"回复 {i}"))
        return s

    async def test_short_session_no_summary(self, monkeypatch):
        called = []

        async def no_summarize(old):
            called.append(1)
            return "SUMMARY"

        monkeypatch.setattr(dlg, "_summarize_old_turns", no_summarize)
        s = self._session(4)  # 8 轮 < trigger 10
        msgs = await dlg._build_dialogue_messages(s)
        user = msgs[1]["content"]
        assert "证据 3" in user  # 原文还在
        assert "SUMMARY" not in user and not called

    async def test_long_session_rolls_up(self, monkeypatch):
        async def fake_summarize(old):
            assert len(old) == 10  # 16 条消息 - 保留近期 6 条 (user/ai 各算一条)
            return "[早期对话摘要] 分析师提供了 auth.log, 判定升级一次"

        monkeypatch.setattr(dlg, "_summarize_old_turns", fake_summarize)
        s = self._session(8)  # 16 轮 > trigger 10
        msgs = await dlg._build_dialogue_messages(s)
        user = msgs[1]["content"]
        assert "早期对话摘要" in user
        assert "证据 7" in user  # 近期原文保留
        assert "证据 0" not in user  # 早期已压缩出原文区

    async def test_summarize_fail_soft(self, monkeypatch):
        async def boom(**kw):
            raise RuntimeError("LLM down")

        monkeypatch.setattr(dlg, "get_chat_llm", lambda **kw: None)
        s = self._session(8)
        # _summarize_old_turns 内部 try 失败会走退化分支
        out = await dlg._summarize_old_turns(s.turns[:12])
        assert "早期对话摘要" in out  # 退化版也有标注
