"""钓鱼邮件分析测试 — 全离线 (确定性解析层真实跑, LLM 边界 mock)."""

from __future__ import annotations

import asyncio

import app.security.email_triage as et
from app.security.email_triage import (
    EmailIndicator,
    EmailVerdict,
    analyze_email,
    build_verification_playbook,
    deterministic_signals,
    parse_email,
)

# 一封典型钓鱼邮件 .eml (凭据钓鱼: 显示名仿冒微软 + Reply-To 不一致 + 裸 IP 链接)
# Return-Path 域须与 From 域不同 — 同域时该信号按设计不触发 (review 发现的 fixture 缺陷)
_PHISH_EML = """Return-Path: <bounce@ret-mailer.xyz>
Received: from unknown (HELO mail-verify-secure.xyz) (192.0.2.66)
From: "Microsoft Security Team <security@microsoft.com>" <no-reply@mail-verify-secure.xyz>
Reply-To: support.recovery@totally-not-evil.top
To: victim@corp.example
Subject: =?utf-8?B?6aG65LuL5L+h5Dp55LqG5piv5a6d6ZSB5Liq6Zeu6aKY?=
Date: Thu, 22 Oct 2026 10:00:00 +0800
Message-ID: <abc@mail-verify-secure.xyz>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Dear User,

Your account will be suspended in 24 hours. Please verify your password immediately:
http://192.0.2.99/office365/login?redirect=verify

Sincerely,
Microsoft Account Team
"""

_SPAM_TEXT = """From: promo@deals-newsletter.shop
Subject: 限时 3 折! 全场包邮最后一天

亲爱的会员:
双 12 大促最后 24 小时, 全场 3 折起, 点击抢购 http://deals-newsletter.shop/sale
退订请回复 TD
"""

_BEC_TEXT = """From: "CEO Zhang Wei" <zhangwei.ceo@qq-mail.xyz>
Reply-To: ceo.private.mail@quickmail.top
Subject: 在吗? 有笔急款需要你处理

我是张伟, 在开董事会不方便打电话。供应商催一笔 48 万合同款,
你先安排财务今天转到: 农行 6228 4812 3456 7890 (王经理)
"""


# ---------- 确定性解析 ----------

def test_parse_eml_headers_and_body():
    p = parse_email(_PHISH_EML)
    h = p["headers"]
    assert "mail-verify-secure.xyz" in h["From"]
    assert h["Reply-To"] == "support.recovery@totally-not-evil.top"
    assert "verify your password" in p["body"]
    assert any("192.0.2.99" in u for u in p["urls"])
    assert p["received_count"] >= 1


def test_parse_excerpt_fallback():
    # 非 eml 纯摘录: 逐行提取 header
    p = parse_email(_SPAM_TEXT)
    assert "promo@deals-newsletter.shop" in (p["headers"].get("From") or "")
    assert "大促" in p["body"] or "抢购" in p["body"]


def test_signals_spoof_and_link():
    sigs = deterministic_signals(parse_email(_PHISH_EML))
    cats = [s["category"] for s in sigs]
    # 显示名仿冒品牌 (microsoft 在显示名, 发件域不同)
    assert "sender_spoof" in cats
    # Reply-To 域不一致
    assert any("Reply-To" in s["evidence"] or "回复地址" in s["description"] for s in sigs)
    # 裸 IP 链接
    assert any("192.0.2.99" in s["evidence"] for s in sigs)
    # 每条信号都带证据
    assert all(s["evidence"] for s in sigs)


def test_signals_return_path_mismatch():
    sigs = deterministic_signals(parse_email(_PHISH_EML))
    assert any("Return-Path" in s["evidence"] for s in sigs)


def test_signals_dangerous_attachment_and_double_ext():
    text = """From: a@b.com
Subject: invoice

Please see attached invoice.
"""
    p = parse_email(text + "\nattachment: Invoice_2026.pdf.exe\nalso update.docm")
    sigs = deterministic_signals(p)
    cats = [s["category"] for s in sigs]
    assert "dangerous_attachment" in cats
    assert any("双扩展名" in s["description"] for s in sigs)
    assert any("宏" in s["description"] for s in sigs)


def test_signals_shortener_and_punycode():
    text = "From: a@b.com\nSubject: hi\n\nclick https://bit.ly/3xYz and http://xn--pypal-4ve.com/login"
    sigs = deterministic_signals(parse_email(text))
    descs = " ".join(s["description"] for s in sigs)
    assert "短链" in descs
    assert "punycode" in descs


def test_signals_bec_reply_to_mismatch():
    sigs = deterministic_signals(parse_email(_BEC_TEXT))
    assert any("回复地址" in s["description"] for s in sigs)


def test_signals_clean_email_no_hits():
    text = "From: colleague@corp.example\nSubject: 周会纪要\n\n见附件, 周三评审。http://corp.example/wiki/123"
    sigs = deterministic_signals(parse_email(text))
    assert sigs == []


# ---------- 枚举归一 (LLM 自造词防线) ----------

def test_verdict_enum_normalization():
    v = EmailVerdict.model_validate({
        "classification": "恶意邮件", "confidence": 0.9, "phishing_type": "凭据钓鱼",
        "intent_summary": "x", "indicators": [], "spoofing_analysis": "y", "verdict_reason": "z",
    })
    assert v.classification == "phishing"
    assert v.phishing_type == "credential_phishing"


def test_verdict_invalid_enum_defaults():
    v = EmailVerdict.model_validate({
        "classification": "超级危险", "phishing_type": "新类型",
        "intent_summary": "x", "indicators": [], "spoofing_analysis": "y", "verdict_reason": "z",
    })
    # 非法词不猜方向 — 归 suspicious (宁可疑勿漏)
    assert v.classification == "suspicious"
    assert v.phishing_type == "none"


# ---------- analyze_email (mock LLM) ----------

def _fake_llm(verdict: EmailVerdict):
    async def fake_structured(**kwargs):
        return verdict
    return fake_structured


def test_analyze_llm_ok(monkeypatch):
    v = EmailVerdict(
        classification="phishing", confidence=0.92, phishing_type="credential_phishing",
        intent_summary="骗取 Office365 密码",
        indicators=[
            EmailIndicator(category="sender_spoof", description="仿冒微软",
                           evidence="From: \"Microsoft Security Team <security@microsoft.com>\" <no-reply@mail-verify-secure.xyz>"),
            EmailIndicator(category="link_mismatch", description="裸 IP 链接",
                           evidence="http://192.0.2.99/office365/login?redirect=verify"),
        ],
        spoofing_analysis="显示名含 microsoft.com 但发件域是 mail-verify-secure.xyz",
        verdict_reason="身份伪造+裸 IP 凭据索取",
    )
    monkeypatch.setattr(et, "ainvoke_structured", _fake_llm(v))
    r = asyncio.run(analyze_email(_PHISH_EML))
    assert r["status"] == "ok"
    assert r["classification"] == "phishing"
    assert r["phishing_type"] == "credential_phishing"
    # 真实证据保留
    assert len(r["indicators"]) == 2
    # 验证剧本自动填充
    pb = r["verification_playbook"]
    assert "192.0.2.99" in str(pb["targets"])
    assert pb["link_verification"]  # 有链接 → 链接剧本在
    assert not pb["attachment_verification"]  # 无附件 → 附件剧本空


def test_analyze_drops_hallucinated_evidence(monkeypatch):
    v = EmailVerdict(
        classification="phishing", confidence=0.9, phishing_type="credential_phishing",
        intent_summary="x",
        indicators=[
            EmailIndicator(category="urgency_tactic", description="编造的证据",
                           evidence="这句原文里根本没有出现 12345678"),
        ],
        spoofing_analysis="y", verdict_reason="z",
    )
    monkeypatch.setattr(et, "ainvoke_structured", _fake_llm(v))
    r = asyncio.run(analyze_email(_PHISH_EML))
    # 幻觉引用被丢, 确定性信号兜底 indicators 不为空
    assert all("根本没有" not in i["evidence"] for i in r["indicators"])
    assert r["indicators"]  # 确定性信号补位


def test_analyze_llm_fail_degrades_to_signals(monkeypatch):
    async def boom(**kwargs):
        raise RuntimeError("llm down")
    monkeypatch.setattr(et, "ainvoke_structured", boom)
    r = asyncio.run(analyze_email(_PHISH_EML))
    assert r["status"] == "degraded"
    assert r["classification"] == "suspicious"
    assert r["indicators"]  # 确定性信号仍在
    assert r["verification_playbook"]["link_verification"]


def test_verdict_playbook_attachment_filled():
    p = parse_email("From: a@b.com\nSubject: x\n\nsee Invoice.pdf.exe attached")
    pb = build_verification_playbook(p)
    assert pb["attachment_verification"]
    assert any("哈希" in s["step"] for s in pb["attachment_verification"])
    # 剧本零自动访问: 全是指引/命令/情报链接, 无任何自动 fetch
    assert "principle" in pb


def test_analyze_bec_text(monkeypatch):
    v = EmailVerdict(
        classification="phishing", confidence=0.88, phishing_type="bec_fraud",
        intent_summary="冒充 CEO 骗转账",
        indicators=[EmailIndicator(category="sender_spoof", description="Reply-To 不一致",
                                   evidence="Reply-To: ceo.private.mail@quickmail.top")],
        spoofing_analysis="显示名 CEO, 域 qq-mail.xyz 仿 qq.com, 回信到 quickmail.top",
        verdict_reason="冒充高管+急款话术+第三方收款",
    )
    monkeypatch.setattr(et, "ainvoke_structured", _fake_llm(v))
    r = asyncio.run(analyze_email(_BEC_TEXT))
    assert r["classification"] == "phishing"
    assert r["phishing_type"] == "bec_fraud"


# ---------- API 端点 ----------

def test_api_email_triage_sse(monkeypatch, tmp_path_factory):
    # 隔离历史落盘: SSE 全流程会 append, 不 patch 会写真实 data/email_history.jsonl
    import app.security.email_history as _eh
    monkeypatch.setattr(_eh, "_EMAIL_HISTORY", tmp_path_factory.mktemp("emh") / "h.jsonl")

    from fastapi.testclient import TestClient

    from app.config import settings
    from app.main import app

    # 沙箱验证必须隔离 — 本地 .env 配了 URLSCAN_API_KEY 时会真实外呼 urlscan.io
    # 且事件序列多出 verifying, 断言必挂 (review 实测的环境敏感回归)
    monkeypatch.setattr(settings, "urlscan_api_key", "")

    v = EmailVerdict(
        classification="spam", confidence=0.8, phishing_type="none",
        intent_summary="促销", indicators=[], spoofing_analysis="一致",
        verdict_reason="正常营销域名群发",
    )
    monkeypatch.setattr(et, "ainvoke_structured", _fake_llm(v))
    client = TestClient(app)
    resp = client.post("/api/v1/secops/email/triage", json={"raw_email": _SPAM_TEXT})
    assert resp.status_code == 200
    # SSE: 事件序列完整
    events = [line[6:] for line in resp.text.splitlines() if line.startswith("data: ")]
    import json
    stages = [json.loads(e).get("stage") for e in events]
    assert stages == ["start", "parsing", "analyzing", "report", "complete"]
    report = [json.loads(e) for e in events if json.loads(e).get("stage") == "report"][0]
    assert report["result"]["classification"] == "spam"


# ---------- 沉淀注入 (批 4): 空态字节一致 + 注入文案纪律 ----------

from app.security.email_triage import _USER_TMPL

_OLD_TMPL = """{untrusted_block}

【代码层确定性信号 (已验证事实)】
{signals_block}
{sandbox_block}
请输出结构化研判 (EmailVerdict)。"""


def test_inject_empty_state_byte_identical():
    """三个注入参数全空时, 渲染结果与旧管线逐字节一致 (回归保障)."""
    new = _USER_TMPL.format(
        untrusted_block="U", signals_block="S",
        history_block="", sandbox_block="", experience_block="",
    )
    old = _OLD_TMPL.format(untrusted_block="U", signals_block="S", sandbox_block="")
    assert new == old


def test_inject_blocks_copywriting_discipline():
    """注入态文案纪律: 历史=已验证事实, 经验=仅供参考不可单独定性 (评测 4.2)."""
    rendered = _USER_TMPL.format(
        untrusted_block="U", signals_block="S",
        history_block="\n\n【同发件域历史判定 (本系统历史记录, 已验证事实)】\n域 X 有 3 次",
        sandbox_block="\n\n【链接沙箱验证 (第三方 urlscan 代访的已验证事实 — 与确定性信号同等采纳)】\n- 沙箱",
        experience_block="\n\n【同类邮件历史研判经验 (仅供参考, 不可单独作为定性依据 — 需以本案证据为准)】\n# 经验",
    )
    assert "已验证事实" in rendered
    assert "仅供参考, 不可单独作为定性依据" in rendered
    assert "域 X 有 3 次" in rendered and "# 经验" in rendered
