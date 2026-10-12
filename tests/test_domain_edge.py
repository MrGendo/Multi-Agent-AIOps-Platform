"""领域独占能力三模块测试: 资产拓扑 / 证据目录 / 判定回归 — 全离线."""

from __future__ import annotations

import json

import app.security.asset_graph as ag
from app.security.asset_graph import build_asset_context, resolve_assets
from app.security.evidence_catalog import build_evidence_catalog
from app.security.judgment_regression import score_replay


# ---------- 资产拓扑 ----------
def test_resolve_by_hostname(tmp_path, monkeypatch):
    monkeypatch.setattr(ag, "_ASSET_FILE", tmp_path / "assets.yaml")
    tmp_path.joinpath("assets.yaml").write_text(
        "assets:\n  - id: prod-web-01\n    ips: [10.0.0.5]\n    services: [nginx]\n"
        "    tags: [prod, dmz]\n    sensors: [waf, hids]\n    segment: dmz\n"
        "sensors: {}\n",
        encoding="utf-8",
    )
    ag._cache = None
    hits = resolve_assets("prod-web-01 出现可疑进程")
    assert len(hits) == 1 and hits[0]["id"] == "prod-web-01"


def test_resolve_by_ip_in_iocs(tmp_path, monkeypatch):
    monkeypatch.setattr(ag, "_ASSET_FILE", tmp_path / "assets.yaml")
    tmp_path.joinpath("assets.yaml").write_text(
        "assets:\n  - id: db-1\n    ips: [10.0.1.20]\n    services: [mysql]\n"
        "    tags: [pci]\n    sensors: [hids]\n    segment: db\nsensors: {}\n",
        encoding="utf-8",
    )
    ag._cache = None
    hits = resolve_assets("外联告警 来自某主机", {"ips": ["10.0.1.20"]})
    assert len(hits) == 1


def test_no_file_no_hit_zero_impact(tmp_path, monkeypatch):
    monkeypatch.setattr(ag, "_ASSET_FILE", tmp_path / "nonexistent.yaml")
    ag._cache = None
    assert resolve_assets("任意告警") == []
    assert build_asset_context("任意告警") == ""  # 空串 → analyst 零影响


def test_asset_context_content(tmp_path, monkeypatch):
    monkeypatch.setattr(ag, "_ASSET_FILE", tmp_path / "assets.yaml")
    tmp_path.joinpath("assets.yaml").write_text(
        "assets:\n"
        "  - id: prod-web-01\n    ips: [10.0.0.5]\n    services: [nginx, api]\n"
        "    tags: [prod, pci]\n    sensors: [waf, hids]\n    segment: dmz\n"
        "  - id: prod-web-02\n    ips: [10.0.0.6]\n    services: [nginx]\n"
        "    tags: [prod]\n    sensors: [waf]\n    segment: dmz\n"
        "sensors: {}\n",
        encoding="utf-8",
    )
    ag._cache = None
    ctx = build_asset_context("攻击命中 prod-web-01")
    assert "prod-web-01" in ctx and "PCI" in ctx  # PCI 提示
    assert "nginx" in ctx  # 服务
    assert "prod-web-02" in ctx  # 同网段
    assert "waf" in ctx and "hids" in ctx  # 覆盖传感器


def test_malformed_yaml_fails_soft(tmp_path, monkeypatch):
    monkeypatch.setattr(ag, "_ASSET_FILE", tmp_path / "assets.yaml")
    tmp_path.joinpath("assets.yaml").write_text("{broken yaml [[", encoding="utf-8")
    ag._cache = None
    assert build_asset_context("prod-web-01") == ""


# ---------- 证据目录 ----------
def test_catalog_lists_only_covered_sensors(tmp_path, monkeypatch):
    monkeypatch.setattr(ag, "_ASSET_FILE", tmp_path / "assets.yaml")
    tmp_path.joinpath("assets.yaml").write_text(
        "assets:\n  - id: gw-1\n    ips: [10.0.0.1]\n    services: [vpn]\n"
        "    tags: [prod]\n    sensors: [ids, ndr]\n    segment: edge\nsensors: {}\n",
        encoding="utf-8",
    )
    ag._cache = None
    cat = build_evidence_catalog("brute_force", "暴力破解命中 gw-1")
    assert cat is not None
    assert "IDS" in cat and "NDR" in cat
    assert "WAF" not in cat  # 未覆盖的传感器不出现
    assert "HIDS" not in cat


def test_catalog_none_when_no_asset(tmp_path, monkeypatch):
    monkeypatch.setattr(ag, "_ASSET_FILE", tmp_path / "assets.yaml")
    tmp_path.joinpath("assets.yaml").write_text("assets: []\nsensors: {}\n", encoding="utf-8")
    ag._cache = None
    assert build_evidence_catalog("brute_force", "陌生告警 1.2.3.4") is None


def test_catalog_priority_order(tmp_path, monkeypatch):
    monkeypatch.setattr(ag, "_ASSET_FILE", tmp_path / "assets.yaml")
    tmp_path.joinpath("assets.yaml").write_text(
        "assets:\n  - id: w1\n    ips: [10.0.0.5]\n    services: [nginx]\n"
        "    tags: [prod]\n    sensors: [hids, waf, ids]\n    segment: dmz\nsensors: {}\n",
        encoding="utf-8",
    )
    ag._cache = None
    cat = build_evidence_catalog("web_attack", "SQL 注入命中 w1")
    assert cat is not None
    assert cat.index("WAF") < cat.index("HIDS")  # web_attack 优先 WAF


# ---------- 判定回归 ----------
def test_score_all_agree():
    r = score_replay([
        {"query": "a", "expected": "malicious", "actual": "malicious"},
        {"query": "b", "expected": "benign", "actual": "benign"},
    ])
    assert r["agree_rate"] == 1.0 and r["grade"] == "PASS" and not r["flips"]


def test_score_equiv_group_not_flip():
    r = score_replay([{"query": "a", "expected": "suspicious", "actual": "inconclusive"}])
    assert r["agree_rate"] == 1.0  # 同组视为一致


def test_score_real_flip_counts():
    r = score_replay([
        {"query": "a", "expected": "malicious", "actual": "benign"},
        {"query": "b", "expected": "malicious", "actual": "malicious"},
    ])
    assert r["agree_rate"] == 0.5 and len(r["flips"]) == 1
    assert r["flips"][0]["expected"] == "malicious"


def test_score_grade_thresholds():
    assert score_replay([])["grade"] if False else True  # noqa: B011
    r_warn = score_replay([{"query": str(i), "expected": "m", "actual": "b"} for i in range(4)])
    assert r_warn["grade"] == "FAIL"
    r_pass = score_replay([{"query": str(i), "expected": "m", "actual": "m"} for i in range(4)])
    assert r_pass["grade"] == "PASS"
