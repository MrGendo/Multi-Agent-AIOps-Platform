"""邮件研判历史模块测试 — 落盘/尾读查询/同域统计 (全部离线, 不碰真实数据文件)."""

import json

import app.security.email_history as eh
from app.security.email_history import append, query, sender_domain_stats


def test_append_and_tail_query(tmp_path, monkeypatch):
    monkeypatch.setattr(eh, "_EMAIL_HISTORY", tmp_path / "email_history.jsonl")
    for i in range(25):
        append(
            classification="phishing" if i % 2 else "benign",
            phishing_type="credential_phishing" if i % 2 else "",
            confidence=0.8, sender_domain=f"dom{i % 3}.example",
            from_header=f"a@dom{i % 3}.example", subject=f"s{i}",
        )
    rows = query(limit=10)
    assert len(rows) == 10
    assert rows[0]["subject"] == "s24"      # 新→旧
    assert rows[-1]["subject"] == "s15"
    # 尾读正确性: 与全量文件倒序一致
    all_lines = [json.loads(l) for l in (tmp_path / "email_history.jsonl").read_text().splitlines()]
    assert [r["subject"] for r in query(limit=25)] == [r["subject"] for r in reversed(all_lines)]


def test_domain_stats_window_and_counts(tmp_path, monkeypatch):
    monkeypatch.setattr(eh, "_EMAIL_HISTORY", tmp_path / "email_history.jsonl")
    append(classification="phishing", sender_domain="evil.example", phishing_type="bec_fraud")
    append(classification="phishing", sender_domain="evil.example")
    append(classification="benign", sender_domain="good.example")
    stats = sender_domain_stats("evil.example", days=90)
    assert stats["total"] == 2
    assert stats["by_classification"] == {"phishing": 2}
    assert sender_domain_stats("good.example")["total"] == 1
    assert sender_domain_stats("never.example")["total"] == 0


def test_query_empty_or_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(eh, "_EMAIL_HISTORY", tmp_path / "none.jsonl")
    assert query(10) == []
    assert sender_domain_stats("x.example")["total"] == 0
