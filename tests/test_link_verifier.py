"""链接沙箱验证 (urlscan) 单元测试 — 全程 mock httpx, 零真实网络请求.

覆盖: 无 key 短路 / 正常判定 / 轮询超时 / 429 超额 / verdict 字段缺失容忍 /
SSE 流的 auto_verify 两态 (不配置 key 时行为与现状完全一致).
"""

import asyncio
import json

import pytest

import app.security.link_verifier as lv
from app.config import settings


def _set_key(monkeypatch, key="test-key"):
    monkeypatch.setattr(settings, "urlscan_api_key", key)
    monkeypatch.setattr(settings, "urlscan_visibility", "public")


def _fast_poll(monkeypatch):
    """压缩轮询节奏, 让超时用例毫秒级完成."""
    monkeypatch.setattr(lv, "_POLL_INTERVAL_SEC", 0.01)
    monkeypatch.setattr(lv, "_TOTAL_BUDGET_SEC", 0.05)


class _Resp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeClient:
    """按脚本回放的 httpx.AsyncClient 桩: post 一次, get 依序回放."""

    def __init__(self, post_resp, get_resps):
        self._post_resp = post_resp
        self._get_resps = list(get_resps)
        self.post_calls = []
        self.get_urls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, **kw):
        self.post_calls.append((url, kw))
        return self._post_resp

    async def get(self, url, **kw):
        self.get_urls.append(url)
        return self._get_resps.pop(0) if self._get_resps else _Resp(404)


@pytest.fixture
def patch_client(monkeypatch, tmp_path_factory):
    def _patch(client):
        # 注意: 桩必须是同步函数 — 真实 AsyncClient(...) 构造调用返回
        # context manager 而非 coroutine, async with 才能成立
        def fake_client(*a, **kw):
            return client
        monkeypatch.setattr(lv.httpx, "AsyncClient", fake_client)
        return client
    return _patch


# ---------- 无 key 短路 ----------

def test_no_key_returns_empty(monkeypatch):
    _set_key(monkeypatch, key="")
    result = asyncio.run(lv.verify_urls(["http://a.com/x"]))
    assert result == []


# ---------- 正常判定 ----------

def test_verify_ok_malicious(monkeypatch, patch_client):
    _set_key(monkeypatch)
    _fast_poll(monkeypatch)
    client = _FakeClient(
        post_resp=_Resp(200, {"uuid": "u-123"}),
        get_resps=[_Resp(404), _Resp(200, {
            "verdicts": {"overall": {"malicious": True}, "urlscan": {"score": 82, "categories": ["Phishing"]}},
            "page": {"url": "http://final.example/login", "domainAgeDays": 3},
        })],
    )
    patch_client(client)
    results = asyncio.run(lv.verify_urls(["http://bad.example/x"]))
    assert len(results) == 1
    r = results[0]
    assert r["status"] == "verified"
    assert r["malicious"] is True
    assert r["score"] == 82
    assert r["categories"] == ["Phishing"]
    assert r["final_url"] == "http://final.example/login"
    assert r["domain_age_days"] == 3
    assert r["screenshot"] == "https://urlscan.io/screenshots/u-123.png"
    # OPSEC: 提交目标只允许 urlscan.io
    assert client.post_calls[0][0] == "https://urlscan.io/api/v1/scan/"


def test_verify_clean_by_score(monkeypatch, patch_client):
    _set_key(monkeypatch)
    _fast_poll(monkeypatch)
    patch_client(_FakeClient(
        post_resp=_Resp(200, {"uuid": "u-2"}),
        get_resps=[_Resp(200, {
            "verdicts": {"urlscan": {"score": -5}},
            "page": {"url": "https://good.example/"},
        })],
    ))
    r = asyncio.run(lv.verify_urls(["https://good.example/"]))[0]
    assert r["malicious"] is False   # overall.malicious 缺失 → score<=0 推断干净


# ---------- 超时 / 429 fail-soft ----------

def test_verify_timeout_skipped(monkeypatch, patch_client):
    _set_key(monkeypatch)
    _fast_poll(monkeypatch)
    patch_client(_FakeClient(post_resp=_Resp(200, {"uuid": "u-3"}), get_resps=[]))
    r = asyncio.run(lv.verify_urls(["http://slow.example/"]))[0]
    assert r["status"] == "skipped"
    assert "超时" in r["error"]


def test_verify_429_quota_error(monkeypatch, patch_client):
    _set_key(monkeypatch)
    _fast_poll(monkeypatch)
    patch_client(_FakeClient(post_resp=_Resp(429), get_resps=[]))
    r = asyncio.run(lv.verify_urls(["http://q.example/"]))[0]
    assert r["status"] == "error"
    assert "429" in r["error"]


# ---------- 域名去重 + limit ----------

def test_private_address_skipped_without_submit(monkeypatch, patch_client):
    """内网/回环地址不提交沙箱 — 公网扫描器不可达, 提交只会得到假"干净"."""
    _set_key(monkeypatch)
    _fast_poll(monkeypatch)
    client = _FakeClient(post_resp=_Resp(200, {"uuid": "u"}), get_resps=[])
    patch_client(client)
    urls = ["http://192.168.1.99/debug", "http://10.0.0.5/x",
            "http://localhost:8080/a", "https://example.com/z"]
    results = asyncio.run(lv.verify_urls(urls))
    by_url = {r["url"]: r for r in results}
    # 私网/回环 → skipped 且不消耗提交次数
    assert by_url["http://192.168.1.99/debug"]["status"] == "skipped"
    assert "不可达" in by_url["http://192.168.1.99/debug"]["error"]
    assert by_url["http://localhost:8080/a"]["status"] == "skipped"
    # 公网域名正常提交 (只有 example.com 会 post), 无回放 → 轮询超时
    assert len(client.post_calls) == 1
    assert by_url["https://example.com/z"]["status"] == "skipped"


def test_dedup_and_limit(monkeypatch, patch_client):
    _set_key(monkeypatch)
    _fast_poll(monkeypatch)
    client = _FakeClient(
        post_resp=_Resp(200, {"uuid": "u"}),
        get_resps=[_Resp(200, {"verdicts": {}, "page": {}})] * 10,
    )
    patch_client(client)
    urls = [
        "http://a.com/1", "http://a.com/2",   # 同域只取 1 条
        "http://b.com/1", "http://c.com/1", "http://d.com/1",  # 超过 limit=3 截断
    ]
    results = asyncio.run(lv.verify_urls(urls))
    assert [r["url"] for r in results] == ["http://a.com/1", "http://b.com/1", "http://c.com/1"]


# ---------- SSE: 无 key 时行为与现状一致 ----------

def test_sse_no_key_skips_verify_events(monkeypatch, tmp_path_factory):

    # 隔离历史落盘: SSE 全流程会 append, 不 patch 会写真实 data/email_history.jsonl
    import app.security.email_history as _eh
    monkeypatch.setattr(_eh, "_EMAIL_HISTORY", tmp_path_factory.mktemp("emh") / "h.jsonl")

    from app.api.v1 import secops as secops_api
    monkeypatch.setattr(settings, "urlscan_api_key", "")
    # LLM mock: 避免 429/网络拖慢
    from app.security.email_triage import EmailIndicator, EmailVerdict
    verdict = EmailVerdict(
        classification="suspicious", confidence=0.5, phishing_type="none",
        intent_summary="t", indicators=[], spoofing_analysis="s", verdict_reason="r",
    )
    async def fake_structured(**kw):
        return verdict
    monkeypatch.setattr(
        "app.security.email_triage.ainvoke_structured", fake_structured
    )

    async def collect():
        return [ev async for ev in secops_api._run_email_triage_sse(
            "From: a@b.com\nSubject: s\n\nsee http://x.com/y", "", "t-session")]

    events = asyncio.run(collect())
    names = [e["event"] for e in events]
    payload = [json.loads(e["data"]) for e in events]
    assert "verifying" not in names and "link_report" not in names
    parsing = next(p for p in payload if p.get("stage") == "parsing")
    assert parsing["auto_verify"] is False


def test_sse_with_key_emits_verify_events(monkeypatch, tmp_path_factory):

    # 隔离历史落盘: SSE 全流程会 append, 不 patch 会写真实 data/email_history.jsonl
    import app.security.email_history as _eh
    monkeypatch.setattr(_eh, "_EMAIL_HISTORY", tmp_path_factory.mktemp("emh") / "h.jsonl")

    from app.api.v1 import secops as secops_api
    monkeypatch.setattr(settings, "urlscan_api_key", "k")
    from app.security.email_triage import EmailVerdict
    verdict = EmailVerdict(
        classification="suspicious", confidence=0.5, phishing_type="none",
        intent_summary="t", indicators=[], spoofing_analysis="s", verdict_reason="r",
    )
    async def fake_structured(**kw):
        return verdict
    monkeypatch.setattr(
        "app.security.email_triage.ainvoke_structured", fake_structured
    )
    sandbox_verdict = {
        "url": "http://x.com/y", "status": "verified", "malicious": True,
        "score": 90, "categories": ["Phishing"], "final_url": None,
        "domain_age_days": None, "screenshot": "https://urlscan.io/screenshots/u.png",
        "form": {"has_password": True, "form_action": "/login", "action_domain": "x.com", "cross_domain": False},
        "judgement": {"claimed_identity": "某大学统一认证", "credential_form": True,
                      "submits_to": "x.com", "impersonation": "impersonating",
                      "impersonation_target": "某大学", "confidence": 0.85, "reasoning": "落地域与声称身份不符"},
    }
    async def fake_bounded(urls, **kw):
        return [sandbox_verdict], []   # (verdicts, cancelled)
    # secops.py 函数内 import → 打模块属性即生效
    monkeypatch.setattr(lv, "verify_urls_bounded", fake_bounded)

    # 捕获 analyze_email 收到的 sandbox_evidence (注入断言)
    import app.security.email_triage as et
    captured = {}
    orig_analyze = et.analyze_email

    async def spy_analyze(raw_email, note="", sandbox_evidence="", **kw):
        captured["sandbox_evidence"] = sandbox_evidence
        return await orig_analyze(raw_email, note=note, sandbox_evidence=sandbox_evidence, **kw)
    monkeypatch.setattr(et, "analyze_email", spy_analyze)

    async def collect():
        return [ev async for ev in secops_api._run_email_triage_sse(
            "From: a@b.com\nSubject: s\n\nsee http://x.com/y", "", "t-session")]

    events = asyncio.run(collect())
    names = [e["event"] for e in events]
    # v2 序列: 沙箱验证在语义研判之前 (证据进研判), 全部完成时不发 link_report
    assert names == ["start", "parsing", "verifying", "analyzing", "report", "complete"]
    payload = [json.loads(e["data"]) for e in events]
    parsing = next(p for p in payload if p.get("stage") == "parsing")
    assert parsing["auto_verify"] is True
    report = next(p for p in payload if p.get("stage") == "report")
    assert report["result"]["sandbox_link_verdicts"][0]["malicious"] is True
    # 沙箱证据注入了 LLM 上下文 (确定性表单 + 视觉仿冒判定都在)
    assert "密码输入框" in captured.get("sandbox_evidence", "")
    assert "仿冒 某大学" in captured.get("sandbox_evidence", "")


def test_sse_sandbox_timeout_degrades_to_no_evidence(monkeypatch, tmp_path_factory):
    """等待窗超时: report 不带沙箱证据, link_report 后补 cancelled, complete 正常."""
    # 隔离历史落盘: SSE 全流程会 append, 不 patch 会写真实 data/email_history.jsonl
    import app.security.email_history as _eh
    monkeypatch.setattr(_eh, "_EMAIL_HISTORY", tmp_path_factory.mktemp("emh") / "h.jsonl")

    from app.api.v1 import secops as secops_api
    monkeypatch.setattr(settings, "urlscan_api_key", "k")
    from app.security.email_triage import EmailVerdict
    verdict = EmailVerdict(
        classification="suspicious", confidence=0.5, phishing_type="none",
        intent_summary="t", indicators=[], spoofing_analysis="s", verdict_reason="r",
    )
    async def fake_structured(**kw):
        return verdict
    monkeypatch.setattr(
        "app.security.email_triage.ainvoke_structured", fake_structured
    )
    async def fake_bounded(urls, **kw):
        return [], ["http://slow.example/y"]   # 全部超时取消
    monkeypatch.setattr(lv, "verify_urls_bounded", fake_bounded)

    import app.security.email_triage as et
    captured = {}
    orig_analyze = et.analyze_email

    async def spy_analyze(raw_email, note="", sandbox_evidence="", **kw):
        captured["sandbox_evidence"] = sandbox_evidence
        return await orig_analyze(raw_email, note=note, sandbox_evidence=sandbox_evidence, **kw)
    monkeypatch.setattr(et, "analyze_email", spy_analyze)

    async def collect():
        return [ev async for ev in secops_api._run_email_triage_sse(
            "From: a@b.com\nSubject: s\n\nsee http://slow.example/y", "", "t-session")]

    events = asyncio.run(collect())
    names = [e["event"] for e in events]
    assert names == ["start", "parsing", "verifying", "analyzing", "report", "link_report", "complete"]
    payload = [json.loads(e["data"]) for e in events]
    report = next(p for p in payload if p.get("stage") == "report")
    assert report["result"]["sandbox_link_verdicts"] == []
    assert captured["sandbox_evidence"] == ""     # 无沙箱证据, LLM 正常研判
    link = next(p for p in payload if p.get("stage") == "link_report")
    assert "超时" in link["message"]
    assert link["link_verdicts"][0]["url"] == "http://slow.example/y"


# ---------- DOM 表单静态检测 (确定性层) ----------

def test_detect_form_password_cross_domain():
    dom = ('<html><body><form action="https://evil.example/collect">'
           '<input name="user"><input type="password" name="pwd"></form></body></html>')
    r = lv.detect_credential_form(dom, "https://good.example/login")
    assert r["has_password"] is True
    assert r["action_domain"] == "evil.example"
    assert r["cross_domain"] is True


def test_detect_form_password_same_domain():
    dom = '<form action="/auth"><input type="password" name="pwd"></form>'
    r = lv.detect_credential_form(dom, "https://newcas.example.edu.cn/cas")
    assert r["has_password"] is True
    assert r["action_domain"] == "newcas.example.edu.cn"   # 相对路径 → 页面域
    assert r["cross_domain"] is False


def test_detect_form_no_password():
    dom = '<form action="/search"><input name="q"></form>'
    r = lv.detect_credential_form(dom, "https://example.com/")
    assert r["has_password"] is False


def test_detect_form_empty_dom():
    r = lv.detect_credential_form("", "https://example.com/")
    assert r["has_password"] is None


# ---------- 视觉判定 (mock LLM + fail-soft) ----------

def test_judge_landing_page_mock(monkeypatch, tmp_path_factory):
    async def fake_structured(llm=None, schema_cls=None, messages=None, model_name=None, **kw):
        return schema_cls(
            claimed_identity="某大学统一身份认证", credential_form=True,
            submits_to="newcas.example.edu.cn", impersonation="仿冒",
            impersonation_target="某大学", confidence=0.9, reasoning="落地域与官方认证域不符",
        )
    import app.core.structured as structured_mod
    monkeypatch.setattr(structured_mod, "ainvoke_structured", fake_structured)
    # judge_landing_page 函数内 import ainvoke_structured → 打模块属性
    import asyncio
    j = asyncio.run(lv.judge_landing_page("ZmFrZQ==", "http://x.y/", {"has_password": True}))
    assert j is not None
    assert j["impersonation"] == "impersonating"   # 中文自造词归一到枚举
    assert j["impersonation_target"] == "某大学"


def test_judge_landing_page_fail_soft(monkeypatch, tmp_path_factory):
    async def boom(**kw):
        raise RuntimeError("LLM 不可用")
    import app.core.structured as structured_mod
    monkeypatch.setattr(structured_mod, "ainvoke_structured", boom)
    import asyncio
    j = asyncio.run(lv.judge_landing_page("ZmFrZQ==", "http://x.y/", {}))
    assert j is None   # fail-soft: 只留确定性表单检测
