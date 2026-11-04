"""推送模块测试 — 三渠道 mock + 阈值/开关/限流 (零真实外呼)."""

import asyncio
import json
from unittest.mock import patch

import httpx
import pytest

import app.core.notifier as nf
from app.config import settings


class _Capture:
    """拦住 notifier 的 HTTP POST, 记录 (url, payload)."""

    def __init__(self):
        self.calls = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((str(request.url), json.loads(request.read())))
        return httpx.Response(200, json={"code": 0})


@pytest.fixture
def notify_on(monkeypatch):
    monkeypatch.setattr(settings, "notify_enabled", True)
    monkeypatch.setattr(settings, "notify_feishu_webhook", "https://open.feishu.cn/hook/test")
    monkeypatch.setattr(settings, "notify_wecom_webhook", "https://qyapi.weixin.qq.com/hook/test")
    monkeypatch.setattr(settings, "notify_smtp_host", "")   # 邮件渠道关闭
    nf._windows.clear()   # 每用例独立限流窗口


def _patch_http(cap):
    """替换 notifier 内的 httpx.Client 为 MockTransport 版 — 先取原类再 patch,
    lambda 里引用 httpx.Client 会解析到 patch 自身造成无限递归 (已踩)."""
    transport = httpx.MockTransport(cap)
    orig = httpx.Client

    def factory(**kw):
        kw.pop("trust_env", None)
        return orig(transport=transport, **kw)

    return patch.object(httpx, "Client", factory)


# ---------- 开关 ----------

def test_disabled_by_default_silent(monkeypatch):
    """默认全关: 不外呼任何渠道 (行为与无此模块一致)."""
    monkeypatch.setattr(settings, "notify_enabled", False)
    assert not nf.should_notify_security("malicious", "CRITICAL")
    assert not nf.should_notify_email("phishing")



def test_threshold_and_malicious_always(notify_on):
    assert nf.should_notify_security("malicious", "LOW") is True    # malicious 恒推
    assert nf.should_notify_security("suspicious", "HIGH") is True  # 达阈值
    assert nf.should_notify_security("benign", "LOW") is False
    assert nf.should_notify_security("suspicious", "MEDIUM") is False


def test_email_phishing_gate(notify_on):
    assert nf.should_notify_email("phishing") is True
    assert nf.should_notify_email("phishing", degraded=True) is False   # 降级不推
    assert nf.should_notify_email("benign") is False


# ---------- 渠道发送 (mock) ----------

def test_notify_security_posts_cards(notify_on):
    cap = _Capture()
    with _patch_http(cap):
        asyncio.run(nf.notify_security(
            verdict="malicious", severity="HIGH", alert_summary="SSH 暴破 from 1.2.3.4",
            reason="14 次失败登录", iocs=["1.2.3.4"],
        ))
    urls = {u for u, _ in cap.calls}
    assert any("feishu" in u for u in urls) and any("qyapi" in u for u in urls)
    feishu = next(p for u, p in cap.calls if "feishu" in u)
    assert feishu["msg_type"] == "interactive"
    title = feishu["card"]["header"]["title"]["content"]
    assert "malicious".upper() in title
    wecom = next(p for u, p in cap.calls if "qyapi" in u)
    assert wecom["msg_type"] == "markdown" and "1.2.3.4" in wecom["markdown"]["content"]


def test_benign_not_sent(notify_on):
    cap = _Capture()
    with _patch_http(cap):
        # should_notify 已在判定层拦截 — 直接验证判定后不触发的完整链路
        if nf.should_notify_security("benign", "LOW"):
            asyncio.run(nf.notify_security("benign", "LOW", "x", "y", []))
    assert cap.calls == []


def test_rate_limit_suppresses_and_summarizes(notify_on):
    """限流: 第 9 条起抑制; 下一窗口首条捎带汇总行."""
    monkey_limit = pytest.MonkeyPatch()
    monkey_limit.setattr(settings, "notify_rate_limit", 2)
    cap = _Capture()
    try:
        with _patch_http(cap):
            for i in range(5):
                asyncio.run(nf.notify_security("malicious", "HIGH", f"alert-{i}", "r", []))
            sent = [p for u, p in cap.calls if "feishu" in u]
            assert len(sent) == 2                     # limit=2, 后 3 条抑制
            # 推进窗口 (60s) → 下一条带汇总行
            nf._windows["feishu"] = (nf._windows["feishu"][0] - 61.0, 2, 3)
            asyncio.run(nf.notify_security("malicious", "HIGH", "after-window", "r", []))
            last = [p for u, p in cap.calls if "feishu" in u][-1]
            content = json.dumps(last, ensure_ascii=False)
            assert "3" in content and "抑制" in content
    finally:
        monkey_limit.undo()


def test_channel_failure_does_not_break_others(notify_on):
    """飞书 500 时企微照发, 且不抛异常."""
    class _Flaky:
        def __init__(self, cap):
            self.cap = cap

        def __call__(self, request):
            if "feishu" in str(request.url):
                return httpx.Response(500)
            return self.cap(request)

    cap = _Capture()
    transport = httpx.MockTransport(_Flaky(cap))
    orig = httpx.Client

    def factory(**kw):
        kw.pop("trust_env", None)
        return orig(transport=transport, **kw)

    with patch.object(httpx, "Client", factory):
        asyncio.run(nf.notify_security("malicious", "HIGH", "a", "r", []))
    assert any("qyapi" in u for u, _ in cap.calls)   # 企微成功
