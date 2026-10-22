"""Sigma 检测规则反哺测试 — 全离线 (mock LLM 边界, tmp 隔离)."""

from __future__ import annotations

import asyncio

import pytest
import yaml

import app.security.sigma_forge as sf
from app.security.sigma_forge import (
    ForgeRequest,
    SigmaRuleDraft,
    SigmaSelector,
    approve_draft,
    forge_from_experience,
    list_drafts,
    render_sigma_yaml,
)

_EXP = (
    "# SSH 爆破 + Tor 出口研判\n"
    "## 攻击模式\n auth.log 短时大量 Failed password, 来源 185.220.101.x (Tor)\n"
    "## 关键指标\n ip=185.220.101.42, rule=5710, 20次/分钟\n"
    "## 判定逻辑\n 失败密度 + Tor 出口 + 无成功记录 → malicious"
)


def _draft(**over):
    d = SigmaRuleDraft(
        title="SSH Brute Force via Tor Exit",
        description="auth.log 高频失败登录且来源为 Tor 出口",
        logsource={"category": "authentication", "product": "linux"},
        selectors=[
            SigmaSelector(
                name="selection_main",
                conditions={"EventID": ["4625"], "IpAddress": ["185.220.101.*"]},
            ),
            SigmaSelector(
                name="filter_benign",
                conditions={"SubjectUserName": ["svc_monitor"]},
            ),
        ],
        condition="selection_main and not filter_benign",
        falsepositives=["监控探针账号"],
        level="high",
        references=["MITRE T1110"],
    )
    return d.model_copy(update=over) if over else d


def _setup(tmp_path, monkeypatch):
    sf._DRAFTS_DIR = tmp_path / "sigma_drafts"
    return monkeypatch


def _fake_llm_ok(monkeypatch, draft):
    async def fake_structured(**kwargs):
        return draft

    monkeypatch.setattr(sf, "ainvoke_structured", fake_structured)


# ---------- 渲染 (确定性, 不经 LLM) ----------

def test_render_valid_sigma_yaml():
    text = render_sigma_yaml(_draft())
    rule = yaml.safe_load(text)
    # Sigma 必备结构
    assert rule["title"] == "SSH Brute Force via Tor Exit"
    assert rule["logsource"]["category"] == "authentication"
    assert rule["detection"]["selection_main"]["EventID"] == ["4625"]
    assert rule["detection"]["condition"] == "selection_main and not filter_benign"
    assert rule["status"] == "experimental"
    assert rule["level"] == "high"
    assert rule["id"]  # 自动生成
    assert rule["falsepositives"] == ["监控探针账号"]


def test_render_sanitizes_bad_names():
    d = _draft(
        selectors=[
            SigmaSelector(name="主 选 择", conditions={"event action": ["x"]}),
        ],
        condition="主 选 择",
    )
    text = render_sigma_yaml(d)
    rule = yaml.safe_load(text)
    assert "主 选 择" not in text
    assert "event action" not in text
    assert list(rule["detection"].keys())[-1] == "condition"
    sel_name = [k for k in rule["detection"] if k != "condition"][0]
    assert rule["detection"]["condition"] == sel_name  # 引用被归一后仍一致


def test_render_unknown_reference_fixed():
    # condition 引用未定义 selector → 渲染器替换为已存在的 selector, 不产出非法规则
    d = _draft(condition="selection_main and not ghost_sel")
    rule = yaml.safe_load(render_sigma_yaml(d))
    assert "ghost_sel" not in rule["detection"]["condition"]
    assert "selection_main" in rule["detection"]["condition"]


def test_render_invalid_level_defaults():
    rule = yaml.safe_load(render_sigma_yaml(_draft(level="超级高")))
    assert rule["level"] == "medium"


def test_conditions_coerce_llm_drift_shapes():
    # E2E 真实抓到的漂移: conditions 给成裸字符串 / 标量值 / k=v 单句
    s1 = SigmaSelector.model_validate({"name": "a", "conditions": "EventID=4625 AND IpAddress=185.220.*"})
    assert s1.conditions == {"EventID": ["4625"], "IpAddress": ["185.220.*"]}
    s2 = SigmaSelector.model_validate({"name": "b", "conditions": {"EventID": "4625"}})
    assert s2.conditions == {"EventID": ["4625"]}
    s3 = SigmaSelector.model_validate({"name": "c", "conditions": "selection_rule5710"})
    # 拆不出 k=v → 整句作为单值兜底 (宁缺勿编: 不丢 selector)
    assert s3.conditions == {"field": ["selection_rule5710"]}


# ---------- 锻造主流程 ----------

def test_forge_persists_draft(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    _fake_llm_ok(monkeypatch, _draft())

    r = asyncio.run(forge_from_experience(ForgeRequest(experience_text=_EXP)))
    assert r["status"] == "ok"
    assert r["drafts"][0]["status"] == "draft"
    assert r["drafts"][0]["sigma_yaml"]
    files = list(sf._DRAFTS_DIR.glob("*.yaml"))
    assert len(files) == 1
    body = yaml.safe_load(files[0].read_text(encoding="utf-8"))
    assert body["_meta"]["status"] == "draft"


def test_forge_idempotent_fingerprint(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    _fake_llm_ok(monkeypatch, _draft())

    r1 = asyncio.run(forge_from_experience(ForgeRequest(experience_text=_EXP)))
    r2 = asyncio.run(forge_from_experience(ForgeRequest(experience_text=_EXP)))
    assert r1["drafts"][0]["fid"] == r2["drafts"][0]["fid"]
    assert r2["drafts"][0]["status"] == "duplicate"
    assert len(list(sf._DRAFTS_DIR.glob("*.yaml"))) == 1


def test_forge_llm_failure_fail_soft(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)

    async def boom(**kwargs):
        raise RuntimeError("llm down")

    monkeypatch.setattr(sf, "ainvoke_structured", boom)
    r = asyncio.run(forge_from_experience(ForgeRequest(experience_text=_EXP)))
    assert r["status"] == "llm_failed"
    assert r["drafts"] == []
    assert not sf._DRAFTS_DIR.exists() or not list(sf._DRAFTS_DIR.glob("*.yaml"))


def test_forge_no_experience(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    # 无入参经验 + 向量库不可用 → no_experience, 不调 LLM
    async def boom(**kwargs):  # pragma: no cover - 调到即失败
        raise AssertionError("不应调 LLM")

    monkeypatch.setattr(sf, "ainvoke_structured", boom)

    import app.core.vector_store as vs

    monkeypatch.setattr(vs, "get_vector_store", lambda: (_ for _ in ()).throw(
        RuntimeError("no milvus")))
    r = asyncio.run(forge_from_experience(ForgeRequest()))
    assert r["status"] == "no_experience"


# ---------- 审批状态机 ----------

def test_approve_flow(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    _fake_llm_ok(monkeypatch, _draft())
    r = asyncio.run(forge_from_experience(ForgeRequest(experience_text=_EXP)))
    fid = r["drafts"][0]["fid"]

    out = approve_draft(fid, reviewer="analyst-zhang", note="规则合理")
    assert out["status"] == "approved"
    assert "不自动下发" in out["message"]

    # 幂等
    out2 = approve_draft(fid)
    assert out2["status"] == "already_approved"

    drafts = list_drafts()["drafts"]
    assert drafts[0]["status"] == "approved"


def test_approve_not_found(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    assert approve_draft("nonexistent")["status"] == "not_found"


# ---------- API 端点 ----------

def test_api_endpoints(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import app

    _setup(tmp_path, monkeypatch)
    _fake_llm_ok(monkeypatch, _draft())

    client = TestClient(app)
    # forge
    resp = client.post("/api/v1/secops/detection/forge", json={"experience_text": _EXP})
    assert resp.status_code == 200
    fid = resp.json()["drafts"][0]["fid"]
    # 列表
    resp = client.get("/api/v1/secops/detection/drafts")
    assert resp.status_code == 200
    assert resp.json()["drafts"][0]["fid"] == fid
    # 审批
    resp = client.post(
        f"/api/v1/secops/detection/drafts/{fid}/approve",
        json={"reviewer": "t", "note": "n"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "approved"
