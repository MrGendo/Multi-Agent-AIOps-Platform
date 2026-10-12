"""传感器覆盖自监测试 — 全离线 (tmp 隔离)."""

from __future__ import annotations

import json
import time

import app.security.asset_graph as ag
import app.security.coverage_watch as cw

_TOPO = """assets:
  - id: web1
    ips: [10.0.0.5]
    services: [nginx]
    tags: [prod]
    sensors: [waf, hids]
    segment: dmz
  - id: gw1
    ips: [10.0.0.1]
    services: [vpn]
    tags: [prod]
    sensors: [ids]
    segment: edge
sensors: {}
"""


def _setup(tmp_path, history_rows):
    import pytest

    ag._cache = None
    cw._HISTORY_FILE = tmp_path / "alert_history.jsonl"
    ag._ASSET_FILE = tmp_path / "assets.yaml"
    tmp_path.joinpath("assets.yaml").write_text(_TOPO, encoding="utf-8")
    if history_rows:
        cw._HISTORY_FILE.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in history_rows) + "\n",
            encoding="utf-8",
        )
    return pytest


def test_no_topology(tmp_path):
    _setup(tmp_path, [])
    ag._ASSET_FILE = tmp_path / "none.yaml"  # 覆盖为不存在
    r = cw.coverage_report()
    assert r["status"] == "no_topology"


def test_all_silent_when_no_history(tmp_path):
    _setup(tmp_path, [])
    r = cw.coverage_report(window_min=30)
    assert r["status"] == "gaps"
    assert set(r["silent_sensors"]) == {"waf", "hids", "ids"}
    assert any("疑似断流" in s["note"] for s in r["sensors"])


def test_recent_event_clears_sensor(tmp_path):
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    _setup(tmp_path, [
        {"kind": "security", "alert": {"kind": "security", "source": "safeline"}, "finished_at": now},
    ])
    r = cw.coverage_report(window_min=30)
    statuses = {s["sensor"]: s["status"] for s in r["sensors"]}
    assert statuses["waf"] == "ok"  # safeline → waf 有事件
    assert statuses["hids"] == "silent"
    assert r["status"] == "gaps"


def test_stale_event_still_silent(tmp_path):
    old = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - 3600))
    _setup(tmp_path, [
        {"kind": "security", "alert": {"kind": "security", "source": "wazuh"}, "finished_at": old},
    ])
    r = cw.coverage_report(window_min=30)
    statuses = {s["sensor"]: s["status"] for s in r["sensors"]}
    assert statuses["hids"] == "silent"  # 1 小时前的事件不在 30 分钟窗口


def test_covered_assets_counted(tmp_path):
    _setup(tmp_path, [])
    r = cw.coverage_report()
    waf = next(s for s in r["sensors"] if s["sensor"] == "waf")
    assert waf["covered_assets"] == 1 and "web1" in waf["assets_sample"]
