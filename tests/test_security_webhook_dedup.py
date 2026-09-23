"""webhook /security 幂等去重测试 (设备告警重发不重复触发研判)."""

from __future__ import annotations

from app.api.v1 import webhook as wh


async def test_security_webhook_dedup_same_fingerprint(monkeypatch):
    """同指纹 5 分钟内第二次 POST 被跳过 (skipped 带 dedup)."""
    # 清掉函数级缓存
    if hasattr(wh.security_webhook, "_seen_fp"):
        del wh.security_webhook._seen_fp

    triggered = []

    class _BT:
        def add_task(self, fn, *a, **kw):
            triggered.append(a[1])

    class _Req:
        async def json(self):
            return {"source": "wazuh", "severity": "HIGH", "rule": "SSH brute",
                    "description": "1.2.3.4 attacking", "fingerprint": "fp-abc"}

    r1 = await wh.security_webhook(_Req(), _BT())
    assert r1["triggered"], "首次应触发研判"
    r2 = await wh.security_webhook(_Req(), _BT())
    assert not r2["triggered"], "同指纹窗口内重复应跳过"
    assert any("dedup" in s for s in r2["skipped"])
    assert len(triggered) == 1


async def test_security_webhook_different_fingerprint_passes(monkeypatch):
    """不同指纹互不影响."""
    if hasattr(wh.security_webhook, "_seen_fp"):
        del wh.security_webhook._seen_fp

    class _BT:
        def add_task(self, fn, *a, **kw):
            pass

    class _Req:
        def __init__(self, desc):
            self._d = desc

        async def json(self):
            return {"source": "generic", "rule": "r", "description": self._d}

    r = await wh.security_webhook(_Req("alert A"), _BT())
    assert r["triggered"]
    r = await wh.security_webhook(_Req("alert B different"), _BT())
    assert r["triggered"], "不同描述=不同指纹, 都应触发"


async def test_security_webhook_window_expiry(monkeypatch):
    """窗口过期后同指纹可再次触发 (滑动窗口 TTL)."""
    import time

    if hasattr(wh.security_webhook, "_seen_fp"):
        del wh.security_webhook._seen_fp

    class _BT:
        def add_task(self, fn, *a, **kw):
            pass

    class _Req:
        async def json(self):
            return {"source": "x", "rule": "r", "description": "same", "fingerprint": "fp-old"}

    await wh.security_webhook(_Req(), _BT())
    # 把已见时间拨回窗口外
    wh.security_webhook._seen_fp["fp-old"] = time.time() - wh._DEDUP_WINDOW_SEC - 1
    r = await wh.security_webhook(_Req(), _BT())
    assert r["triggered"], "窗口外同指纹应重新触发"
