"""研判结果推送 — 飞书/企微群机器人 + SMTP 邮件, 分级触发 + 滑动窗口防轰炸.

纪律:
  - 全 fail-soft: 推送失败只记日志, 绝不影响研判主流程
  - 默认全关: NOTIFY_ENABLED=false 时不外呼任何渠道 (行为与无此模块时一致)
  - 只推"无人值守"路径 (webhook 自动研判 + 邮件管线), UI 手动研判不推 (人在看)
  - httpx/smtp 走 to_thread (批 1 的事件循环阻塞纪律)
"""

from __future__ import annotations

import asyncio
import time
from typing import Dict, Tuple

import httpx
from loguru import logger

from app.config import settings

# ==================== 触发判定 ====================

_SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def should_notify_security(verdict: str, severity: str) -> bool:
    """告警研判是否推送: malicious 恒推, 或严重度达阈值."""
    if not settings.notify_enabled:
        return False
    if (verdict or "").lower() == "malicious":
        return True
    threshold = _SEVERITY_ORDER.get((settings.notify_min_severity or "HIGH").upper(), 3)
    return _SEVERITY_ORDER.get((severity or "").upper(), 0) >= threshold


def should_notify_email(classification: str, degraded: bool = False) -> bool:
    """邮件研判是否推送: phishing 且非降级."""
    return (
        settings.notify_enabled
        and settings.notify_on_phishing
        and classification == "phishing"
        and not degraded
    )


# ==================== 滑动窗口防轰炸 ====================
# 进程内 {渠道: (窗口起点, 已推数, 被抑制数)} — 计数偏差可容忍, 不上锁
# (webhook 告警风暴场景: 超限后抑制, 窗口结束合并推一条汇总)

_windows: Dict[str, Tuple[float, int, int]] = {}


def _admit(channel: str, limit: int) -> bool:
    """是否放行本条; 窗口超限时静默抑制并计数."""
    now = time.monotonic()
    start, sent, suppressed = _windows.get(channel, (now, 0, 0))
    if now - start >= 60.0:
        # 窗口滚动: 保留上一窗抑制数供本轮捎带汇总 (由 _pending_suppressed 读后清零),
        # 不能在这里清零 — 先清会导致汇总行永远读不到
        _windows[channel] = (now, 1, suppressed)
        return True
    if sent >= limit:
        _windows[channel] = (start, sent, suppressed + 1)
        return False
    _windows[channel] = (start, sent + 1, suppressed)
    return True


def _pending_suppressed(channel: str) -> int:
    """当前窗口已抑制条数 (供汇总行捎带; 读后清零避免重复计)."""
    entry = _windows.get(channel)
    if not entry:
        return 0
    start, sent, suppressed = entry
    _windows[channel] = (start, sent, 0)
    return suppressed


# ==================== 渠道发送 ====================

async def _post_json(url: str, payload: Dict) -> None:
    """webhook POST (线程池, 不阻塞事件循环); 飞书/企微都吃 JSON."""
    def _do() -> None:
        with httpx.Client(trust_env=False, timeout=10.0) as client:
            resp = client.post(url, json=payload)
            try:
                resp.raise_for_status()
            except httpx.HTTPStatusError as e:
                # HTTPStatusError 消息含完整 webhook URL (机器人 token) — 401/400
                # 恰是 token 失效高频路径, 转脱敏异常防凭证进日志 (密钥不进日志红线)
                raise RuntimeError(f"HTTP {e.response.status_code}") from None
    await asyncio.to_thread(_do)


def _feishu_card(title: str, level_color: str, lines: list) -> Dict:
    """飞书 interactive 卡片 (红色=恶意/钓鱼, 绿=信息)."""
    return {
        "msg_type": "interactive",
        "card": {
            "header": {"title": {"tag": "plain_text", "content": title},
                       "template": level_color},
            "elements": [
                {"tag": "div", "text": {"tag": "lark_md", "content": ln}} for ln in lines
            ],
        },
    }


def _wecom_markdown(title: str, lines: list) -> Dict:
    """企微 markdown 消息 (同内容降级排版)."""
    return {"msg_type": "markdown", "markdown": {"content": f"## {title}\n" + "\n".join(lines)}}


async def _send_feishu(title: str, lines: list, malicious: bool) -> None:
    url = settings.notify_feishu_webhook
    if not url:
        return
    if _admit("feishu", settings.notify_rate_limit):
        suppressed = _pending_suppressed("feishu")
        if suppressed:
            lines = [*lines, f"> ⏸ 前一分钟另有 **{suppressed}** 条同类告警被限流抑制"]
        await _post_json(url, _feishu_card(title, "red" if malicious else "blue", lines))


async def _send_wecom(title: str, lines: list, malicious: bool) -> None:
    url = settings.notify_wecom_webhook
    if not url:
        return
    if _admit("wecom", settings.notify_rate_limit):
        suppressed = _pending_suppressed("wecom")
        if suppressed:
            lines = [*lines, f"> ⏸ 前一分钟另有 {suppressed} 条同类告警被限流抑制"]
        await _post_json(url, _wecom_markdown(title, lines))


def _send_smtp_sync(title: str, body: str) -> None:
    import smtplib
    from email.mime.text import MIMEText
    from email.header import Header

    host = settings.notify_smtp_host
    if not host:
        return
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = Header(title, "utf-8")
    msg["From"] = settings.notify_smtp_from or settings.notify_smtp_user
    msg["To"] = settings.notify_smtp_to
    port = settings.notify_smtp_port
    with smtplib.SMTP_SSL(host, port, timeout=15) as server:
        if settings.notify_smtp_user:
            server.login(settings.notify_smtp_user, settings.notify_smtp_pass)
        server.sendmail(msg["From"], [t.strip() for t in settings.notify_smtp_to.split(",") if t.strip()], msg.as_string())


async def _send_email(title: str, body: str) -> None:
    if not settings.notify_smtp_host:
        return
    if _admit("smtp", settings.notify_rate_limit):
        await asyncio.to_thread(_send_smtp_sync, title, body)


async def _dispatch(title: str, lines: list, email_body: str, malicious: bool) -> None:
    """三渠道并发, 各自独立 fail-soft."""
    results = await asyncio.gather(
        _send_feishu(title, lines, malicious),
        _send_wecom(title, lines, malicious),
        _send_email(title, email_body),
        return_exceptions=True,
    )
    for name, exc in zip(("feishu", "wecom", "smtp"), results):
        if isinstance(exc, Exception):
            logger.warning(f"[Notify] {name} 推送失败 (fail-soft): {exc}")


# ==================== 对外入口 ====================

async def notify_security(
    verdict: str, severity: str, alert_summary: str, reason: str, iocs: list,
) -> None:
    """告警研判高危结果推送 (webhook 自动研判路径调用)."""
    lines = [
        f"**判定: {verdict.upper()}** · 严重度 {severity}",
        f"**告警**: {alert_summary[:120]}",
        f"**理由**: {reason[:160]}",
    ]
    if iocs:
        lines.append("**IOC**: " + ", ".join(str(i) for i in iocs[:6]))
    lines.append(f"<font color='grey'>来源: 自动研判 webhook · {time.strftime('%H:%M:%S')}</font>")
    body = "\n".join(l.replace("**", "") for l in lines)
    await _dispatch(f"🔴 安全告警: {verdict.upper()}", lines, body, malicious=verdict == "malicious")


async def notify_email(
    classification: str, confidence: float, phishing_type: str,
    intent: str, sender: str, subject: str,
) -> None:
    """钓鱼邮件研判结果推送 (邮件管线调用)."""
    lines = [
        f"**判定: 钓鱼邮件 ({phishing_type or 'phishing'})** · 置信 {confidence:.0%}",
        f"**发件**: {sender[:100]}",
        f"**主题**: {subject[:100]}",
        f"**意图**: {intent[:160]}",
        f"<font color='grey'>来源: 邮件研判管线 · {time.strftime('%H:%M:%S')}</font>",
    ]
    body = "\n".join(l.replace("**", "") for l in lines)
    await _dispatch(f"🔴 钓鱼邮件: {subject[:40]}", lines, body, malicious=True)
