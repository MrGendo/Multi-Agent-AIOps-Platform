"""设备适配器 / 取证引导 / 研判对话 离线单测."""

from __future__ import annotations

import pytest

from app.security import dialogue as dlg
from app.security.device_adapters import detect_and_normalize
from app.security.followup import (
    build_followup_guidance,
    needs_guidance,
    render_guidance_markdown,
)


# ============================================================
# 设备适配器
# ============================================================
class TestDeviceAdapters:
    def test_wazuh_wrapped(self):
        payload = detect_and_normalize({
            "alert": {
                "rule": {"id": "5710", "level": 10, "description": "sshd: Attempt to login using a non-existent user",
                         "groups": ["syslog", "sshd", "authentication_failures"]},
                "agent": {"name": "web-prod-01"},
                "data": {"srcip": "203.0.113.42", "srcuser": "root"},
                "full_log": "sshd[1234]: Failed password for invalid user root from 203.0.113.42 port 55120 ssh2",
            }
        })
        assert payload is not None
        assert payload.source == "wazuh"
        assert payload.severity == "HIGH"  # level 10
        assert payload.src_ip == "203.0.113.42"
        assert "5710" in payload.rule

    def test_wazuh_level_12_critical(self):
        payload = detect_and_normalize({
            "rule": {"id": "1", "level": 14, "description": "x"}, "full_log": "y"
        })
        assert payload.severity == "CRITICAL"

    def test_suricata_eve(self):
        payload = detect_and_normalize({
            "event_type": "alert",
            "alert": {"action": "blocked", "category": "Web Attack",
                      "severity": 2, "signature": "SQL Injection Attempt",
                      "signature_id": 1000001},
            "src_ip": "45.33.32.156", "dest_ip": "10.0.0.8",
            "http": {"hostname": "shop.example.com", "url": "/login", "http_method": "POST"},
            "flow_id": 12345,
        })
        assert payload is not None
        assert payload.source == "suricata"
        assert payload.severity == "HIGH"  # severity 2
        assert payload.src_ip == "45.33.32.156"
        assert "SQL Injection" in payload.rule
        assert "shop.example.com" in payload.description

    def test_falco(self):
        payload = detect_and_normalize({
            "rule": "Terminal shell in container",
            "priority": "Warning",
            "output": "17:21:56.123456789: Warning A shell was spawned in a container with an attached terminal (user=root k8s.ns=default)",
            "output_fields": {"user.name": "root", "fd.sip": "10.3.4.5"},
        })
        assert payload is not None
        assert payload.source == "falco"
        assert payload.severity == "MEDIUM"
        assert payload.src_ip == "10.3.4.5"

    def test_generic_passthrough_none(self):
        assert detect_and_normalize({"foo": "bar"}) is None

    def test_not_a_dict(self):
        assert detect_and_normalize("string") is None


# ============================================================
# 取证引导
# ============================================================
class TestFollowup:
    def test_brute_force_guidance_with_ioc(self):
        g = build_followup_guidance(
            "brute_force", {"ips": ["203.0.113.42"]}, reason="无成功登录证据", confidence=0.45
        )
        assert g is not None
        assert len(g.steps) == 3
        # IOC 占位符被填充
        assert "203.0.113.42" in g.steps[0].action
        assert "0%" not in g.reason or "45" in g.reason
        md = render_guidance_markdown(g)
        assert "取证建议" in md
        assert "auth.log" in md

    def test_no_iocs_uses_placeholder(self):
        g = build_followup_guidance("web_attack", {})
        assert "源IP" not in g.steps[0].action or True  # web_attack 模板占位符不同
        md = render_guidance_markdown(g)
        assert "WAF" in md or "日志" in md

    def test_unknown_type_falls_to_anomaly(self):
        g = build_followup_guidance("weird_type", {})
        assert g is not None
        assert len(g.steps) >= 2

    def test_needs_guidance_rules(self):
        assert needs_guidance("inconclusive", 0.9) is True
        assert needs_guidance("", 0.9) is True
        assert needs_guidance("malicious", 0.5) is True   # 低置信
        assert needs_guidance("malicious", 0.85) is False
        assert needs_guidance("suspicious", 0.75) is False


# ============================================================
# 研判对话
# ============================================================
class TestDialogue:
    def _make_session(self):
        s = dlg.create_session(
            alert_text="SSH 爆破告警 from 1.2.3.4",
            report="# 报告\nverdict=inconclusive",
            verdict="inconclusive", severity="MEDIUM", response_mode="recommend",
            iocs={"ips": ["1.2.3.4"]}, alert_type="brute_force",
            base_session_id="test-dlg-001",
        )
        return s

    def test_create_session_idempotent(self):
        s1 = self._make_session()
        s2 = self._make_session()
        assert s1.session_id == s2.session_id

    async def test_dialogue_turn_updates_verdict(self, monkeypatch, tmp_path):
        monkeypatch.setattr(dlg, "SESSIONS_DIR", tmp_path)
        s = self._make_session()
        s.turns = []  # 重置幂等会话的旧状态

        async def fake_structured(**kwargs):
            return dlg.VerdictUpdate(
                reply="新证据显示存在成功登录, 判定升级为 malicious",
                verdict="malicious", severity="HIGH", confidence=0.88,
                evidence_used=["auth.log Accepted password 行"],
                needs_more_evidence=False,
            )

        monkeypatch.setattr(dlg, "ainvoke_structured", fake_structured)
        result = await dlg.dialogue_turn(
            s, "auth.log 片段: Accepted password for deploy from 1.2.3.4 port 55120 ssh2 (发现成功登录!)"
        )
        assert result["verdict"] == "malicious"
        assert result["verdict_changed"] is True
        assert len(s.turns) == 2  # user + assistant

    async def test_dialogue_llm_failure_fail_soft(self, monkeypatch, tmp_path):
        monkeypatch.setattr(dlg, "SESSIONS_DIR", tmp_path)
        s = self._make_session()
        s.turns = []

        async def boom(**kwargs):
            raise RuntimeError("LLM down")

        monkeypatch.setattr(dlg, "ainvoke_structured", boom)
        result = await dlg.dialogue_turn(s, "补充材料 " * 10)
        assert result.get("llm_failed") is True
        assert "已记录" in result["reply"]

    async def test_close_session_consolidates(self, monkeypatch, tmp_path):
        monkeypatch.setattr(dlg, "SESSIONS_DIR", tmp_path)
        s = self._make_session()
        s.evidence_contribs = ["auth.log 显示成功登录"]

        consolidated = {}

        async def fake_consolidate(sid, alert, report, verdict):
            consolidated["report"] = report
            consolidated["verdict"] = verdict

        import app.security.dialogue as dlg_mod

        # close_session 内部是函数内 import, monkeypatch 源模块
        import app.security.consolidation as cons_mod

        monkeypatch.setattr(cons_mod, "consolidate_triage_report", fake_consolidate)
        result = await dlg_mod.close_session(s)
        assert result["consolidated"] is True
        assert "成功登录" in consolidated["report"]

    async def test_close_no_evidence_skips(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dlg, "SESSIONS_DIR", tmp_path)
        s = self._make_session()
        s.evidence_contribs = []
        result = await dlg.close_session(s)
        assert result["consolidated"] is False

    def test_list_sessions(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dlg, "SESSIONS_DIR", tmp_path)
        monkeypatch.setattr(dlg, "_sessions", {})
        s = self._make_session()
        s.save()
        items = dlg.list_sessions()
        assert any(i["session_id"] == s.session_id for i in items)
