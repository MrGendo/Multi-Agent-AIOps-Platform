"""题单审查驱动的三处补强测试: 处置反哺 / webhook 幂等 / 调查留痕."""

from __future__ import annotations

import json

import app.security.context_provider as cp
from app.security.context_provider import build_prior_history_context


def _write_hist(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n", encoding="utf-8")


def test_disposition_feedback_enters_context(tmp_path, monkeypatch):
    """人工误报标记应出现在同源 IP 的历史统计块 (处置反哺研判)."""
    f = tmp_path / "alert_history.jsonl"
    _write_hist(f, [
        {"kind": "security", "session_id": "s1", "query": "攻击来自 1.2.3.4", "verdict": "malicious",
         "alert": {"kind": "security", "src_ip": "1.2.3.4"}},
        {"kind": "disposition", "session_id": "s1",
         "disposition": {"action": "false_positive", "note": "", "ts": "2026-09-20T12:00:00"}},
        {"kind": "security", "session_id": "s2", "query": "又见 1.2.3.4", "verdict": "suspicious",
         "alert": {"kind": "security", "src_ip": "1.2.3.4"}},
    ])
    monkeypatch.setattr(cp, "_HISTORY_FILE", f)
    out = build_prior_history_context({"ips": ["1.2.3.4"]})
    assert "1.2.3.4" in out
    assert "2 次历史研判" in out
    assert "人工标记误报 x1" in out  # disposition 反哺
    assert "独立研判" in out  # 纪律仍在


def test_resolved_disposition_label(tmp_path, monkeypatch):
    f = tmp_path / "alert_history.jsonl"
    _write_hist(f, [
        {"kind": "security", "session_id": "s1", "query": "5.6.7.8 攻击", "verdict": "malicious",
         "alert": {"kind": "security", "src_ip": "5.6.7.8"}},
        {"kind": "disposition", "session_id": "s1", "disposition": {"action": "resolved"}},
    ])
    monkeypatch.setattr(cp, "_HISTORY_FILE", f)
    out = build_prior_history_context({"ips": ["5.6.7.8"]})
    assert "人工已处置 x1" in out


def test_no_disposition_no_label(tmp_path, monkeypatch):
    f = tmp_path / "alert_history.jsonl"
    _write_hist(f, [
        {"kind": "security", "session_id": "s1", "query": "9.9.9.9", "verdict": "benign",
         "alert": {"kind": "security", "src_ip": "9.9.9.9"}},
    ])
    monkeypatch.setattr(cp, "_HISTORY_FILE", f)
    out = build_prior_history_context({"ips": ["9.9.9.9"]})
    assert "人工标记误报" not in out and "人工已处置" not in out  # 无处置记录不出现统计标签
