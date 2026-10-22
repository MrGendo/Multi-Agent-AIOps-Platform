"""置信度校准 (Confidence Calibration) 测试 — 全离线, tmp 隔离."""

from __future__ import annotations

import json

import app.security.calibration as cal


def _setup(tmp_path, rows):
    cal._HISTORY_FILE = tmp_path / "alert_history.jsonl"
    if rows:
        cal._HISTORY_FILE.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
            encoding="utf-8",
        )


def _triage(sid, verdict, confidence):
    return {
        "session_id": sid,
        "alert": {"kind": "security", "source": "wazuh"},
        "query": f"alert {sid}",
        "verdict": verdict,
        "confidence": confidence,
    }


def _disp(sid, action):
    return {
        "kind": "disposition",
        "session_id": sid,
        "disposition": {"action": action, "note": "", "ts": "2026-10-22T10:00:00"},
    }


def test_no_history_insufficient(tmp_path):
    _setup(tmp_path, [])
    r = cal.calibration_report()
    assert r["status"] == "insufficient_data"
    assert r["sample_count"] == 0


def test_no_disposition_pairs_insufficient(tmp_path):
    # 只有研判记录, 没有人工处置 → 无真值, 诚实返回 insufficient
    _setup(tmp_path, [_triage("s1", "malicious", 0.9)])
    r = cal.calibration_report()
    assert r["status"] == "insufficient_data"


def test_basic_calibration_math(tmp_path):
    # 2 条 malicious 判对 (resolved), 1 条 malicious 判错 (false_positive)
    # 桶 0.9-1.0: conf 0.9, 0.95 → resolved; conf 0.92 → false_positive
    _setup(tmp_path, [
        _triage("s1", "malicious", 0.90), _disp("s1", "resolved"),
        _triage("s2", "malicious", 0.95), _disp("s2", "resolved"),
        _triage("s3", "malicious", 0.92), _disp("s3", "false_positive"),
    ])
    r = cal.calibration_report()
    assert r["status"] == "ok"
    assert r["sample_count"] == 3

    m = r["metrics"]
    # Brier = ((0.9-1)² + (0.95-1)² + (0.92-0)²) / 3
    expected_brier = ((0.9 - 1) ** 2 + (0.95 - 1) ** 2 + (0.92 - 0) ** 2) / 3
    assert abs(m["brier"] - round(expected_brier, 4)) < 1e-6

    # 桶 0.9-1.0: avg_conf=(0.9+0.95+0.92)/3≈0.9233, actual=2/3≈0.6667
    b = r["reliability_buckets"][0]
    assert b["count"] == 3
    assert abs(b["actual_positive_rate"] - 2 / 3) < 1e-3
    assert b["direction"] == "overconfident"
    # ECE = |0.9233 - 0.6667| ≈ 0.2567
    assert abs(m["ece"] - round(abs(0.9233333 - 2 / 3), 4)) < 1e-3

    # 恶意类误报率: 3 条 malicious 里 1 条被标误报
    assert m["false_positive_rate_of_threat_verdicts"] == round(1 / 3, 4)

    # 混淆矩阵
    assert r["verdict_disposition_matrix"]["malicious"] == {
        "resolved": 2, "false_positive": 1}


def test_dlg_prefix_join(tmp_path):
    # 处置登记用 dlg- 前缀会话 id 也要能关联回研判记录
    _setup(tmp_path, [
        _triage("sec-abc", "suspicious", 0.75),
        _disp("dlg-sec-abc", "false_positive"),
    ])
    r = cal.calibration_report()
    assert r["status"] == "ok"
    assert r["sample_count"] == 1
    assert r["verdict_disposition_matrix"]["suspicious"]["false_positive"] == 1


def test_deferred_not_counted(tmp_path):
    # deferred 人工也没结论 → 无真值, 不进校准
    _setup(tmp_path, [
        _triage("s1", "suspicious", 0.7), _disp("s1", "deferred"),
    ])
    r = cal.calibration_report()
    assert r["status"] == "insufficient_data"


def test_old_records_without_confidence_skipped(tmp_path):
    # 补线前落盘的旧研判记录缺 confidence 键 → 跳过 (不拿 0 灌桶)
    rows = [_triage("s1", "malicious", None)]
    rows[0].pop("confidence")
    _setup(tmp_path, rows + [_disp("s1", "resolved")])
    r = cal.calibration_report()
    assert r["status"] == "insufficient_data"


def test_calibrated_direction(tmp_path):
    # 自评 0.3-0.4 桶, 实际全真 → underconfident
    _setup(tmp_path, [
        _triage("s1", "malicious", 0.35), _disp("s1", "resolved"),
        _triage("s2", "malicious", 0.36), _disp("s2", "resolved"),
    ])
    r = cal.calibration_report()
    assert r["reliability_buckets"][0]["direction"] == "underconfident"


def test_api_endpoint_readonly(tmp_path):
    # GET /secops/calibration 纯只读, insufficient_data 也不 5xx
    from fastapi.testclient import TestClient

    from app.main import app

    cal._HISTORY_FILE = tmp_path / "none.jsonl"
    with TestClient(app) as _:
        pass  # 不触发 lifespan (项目纪律: TestClient 不带 with)
    client = TestClient(app)
    resp = client.get("/api/v1/secops/calibration")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] in ("ok", "insufficient_data")
    assert "metrics" in body or "message" in body
