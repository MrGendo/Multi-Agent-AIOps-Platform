"""历史研判记录管理 离线单测 — tmp_path 隔离, 不碰真实 data/."""

from __future__ import annotations

import json
import time
from pathlib import Path

import app.security.correlation as corr
import app.security.dialogue as dlg
from app.security import history_mgmt as hm


def _setup(tmp_path, monkeypatch):
    monkeypatch.setattr(hm, "HISTORY_FILE", tmp_path / "alert_history.jsonl")
    monkeypatch.setattr(dlg, "SESSIONS_DIR", tmp_path / "sessions")
    monkeypatch.setattr(corr, "CORRELATION_DIR", tmp_path / "corr")
    dlg.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    corr.CORRELATION_DIR.mkdir(parents=True, exist_ok=True)


def _mk_json(d: Path, name: str, age_days: float = 0):
    p = d / f"{name}.json"
    p.write_text(json.dumps({"cid": name}), encoding="utf-8")
    old = time.time() - age_days * 86400
    import os

    os.utime(p, (old, old))
    return p


def _mk_hist_line(i: int, *, disposition=None, age_days=0.0):
    ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - age_days * 86400))
    rec = {"kind": "triage", "session_id": f"s{i}", "verdict": "malicious", "finished_at": ts}
    if disposition:
        rec["disposition"] = {"action": disposition, "ts": ts}
    return json.dumps(rec, ensure_ascii=False)


def test_stats_counts(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    hm.HISTORY_FILE.write_text("\n".join([_mk_hist_line(1), _mk_hist_line(2)]) + "\n", encoding="utf-8")
    _mk_json(dlg.SESSIONS_DIR, "dlg-a")
    _mk_json(corr.CORRELATION_DIR, "corr-b")
    s = hm.get_stats()
    assert s["history"]["count"] == 2
    assert s["dialogue"]["count"] == 1
    assert s["correlation"]["count"] == 1
    assert s["history"]["size_bytes"] > 0


def test_purge_by_age(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    _mk_json(dlg.SESSIONS_DIR, "new", age_days=1)
    _mk_json(dlg.SESSIONS_DIR, "old", age_days=60)
    _mk_json(corr.CORRELATION_DIR, "c-old", age_days=60)
    r = hm.purge(targets=["dialogue", "correlation"], keep_days=30)
    assert r["deleted"]["dialogue"] == 1
    assert r["deleted"]["correlation"] == 1
    assert (dlg.SESSIONS_DIR / "new.json").exists()
    assert not (dlg.SESSIONS_DIR / "old.json").exists()


def test_purge_keep_last(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    for i in range(5):
        _mk_json(corr.CORRELATION_DIR, f"c{i}", age_days=i)
    r = hm.purge(targets=["correlation"], keep_last=2)
    assert r["deleted"]["correlation"] == 3
    assert len(list(corr.CORRELATION_DIR.glob("*.json"))) == 2


def test_history_keeps_disposition_rows(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    lines = [
        _mk_hist_line(1, disposition="resolved", age_days=90),  # 老但有处置 → 保
        _mk_hist_line(2, age_days=90),                            # 老无处置 → 删
        _mk_hist_line(3, age_days=1),                             # 新 → 保
    ]
    hm.HISTORY_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    r = hm.purge(targets=["history"], keep_days=30, keep_disposition=True)
    assert r["deleted"]["history"] == 1
    kept = [json.loads(l) for l in hm.HISTORY_FILE.read_text().splitlines() if l.strip()]
    sids = {k["session_id"] for k in kept}
    assert sids == {"s1", "s3"}


def test_history_purge_all_no_disp(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    lines = [
        _mk_hist_line(1, disposition="false_positive"),
        _mk_hist_line(2),
        _mk_hist_line(3),
    ]
    hm.HISTORY_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # 双 0 + 保护开: 只清无 disposition 的行
    r = hm.purge(targets=["history"], keep_days=0, keep_last=0, keep_disposition=True)
    assert r["deleted"]["history"] == 2
    kept = [json.loads(l) for l in hm.HISTORY_FILE.read_text().splitlines() if l.strip()]
    assert len(kept) == 1 and kept[0]["session_id"] == "s1"


def test_corrupt_line_preserved(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    hm.HISTORY_FILE.write_text("{not json}\n" + _mk_hist_line(9) + "\n", encoding="utf-8")
    hm.purge(targets=["history"], keep_days=0, keep_last=0, keep_disposition=False)
    content = hm.HISTORY_FILE.read_text()
    assert "{not json}" in content  # 损坏行不丢 (保守)


def test_delete_session_functions(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    dlg.create_session("告警文本", "# 报告", "malicious", "HIGH", "human_approval", {}, "brute_force", base_session_id="x1")
    assert dlg.delete_session("dlg-x1") is True
    assert dlg.get_session("dlg-x1") is None
    assert dlg.delete_session("dlg-notexist") is False

    corr.create_session("corr-del-1")
    assert corr.delete_session("corr-del-1") is True
    assert corr.get_session("corr-del-1") is None
