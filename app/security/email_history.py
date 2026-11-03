"""钓鱼邮件研判历史 — 落盘/查询/同域统计.

闭环用途 (不止存档): 研判前查同发件域近 N 天历史判定, 作为已验证事实注入
LLM 上下文 — 复发攻击 (同一发件域/同一链接反复投递) 的判定直接受益.

性能纪律 (健康审查 2.1 的教训 — alert_history 全量重读是慢性问题):
query/sender_domain_stats 一律倒序尾读, 只解析需要的行数, 不全量加载.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

_EMAIL_HISTORY = Path(__file__).resolve().parents[2] / "data" / "email_history.jsonl"
_TAIL_BLOCK = 8192   # 尾读块大小 (字节), 覆盖 ~40 条记录


def _read_tail(limit: int) -> List[Dict[str, Any]]:
    """倒序读最后 limit 条记录 — 只解析尾部, 文件增长不影响成本."""
    if not _EMAIL_HISTORY.exists():
        return []
    rows: List[Dict[str, Any]] = []
    with _EMAIL_HISTORY.open("rb") as f:
        f.seek(0, 2)
        size = f.tell()
        pos = size
        buf = b""
        while pos > 0 and len(rows) < limit:
            step = min(_TAIL_BLOCK, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
            # 按行切: 首行可能是残行 (跨块边界), 留给下一轮拼接
            lines = buf.split(b"\n")
            buf = lines.pop(0) if pos > 0 else b""
            for raw in reversed(lines):
                if not raw.strip():
                    continue
                try:
                    rows.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue
                if len(rows) >= limit:
                    break
    return rows   # 新→旧 (循环退出时 buf 必为空: pos==0 时首行已并入解析)


def append(
    classification: str,
    phishing_type: str = "",
    confidence: float = 0.0,
    sender_domain: str = "",
    from_header: str = "",
    subject: str = "",
    url_domains: Optional[List[str]] = None,
    degraded: bool = False,
) -> None:
    """研判完成后追加一行历史 (append-only, 不抛异常阻断主流程)."""
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "classification": classification,
        "phishing_type": phishing_type or "",
        "confidence": round(float(confidence or 0), 3),
        "sender_domain": (sender_domain or "").lower(),
        "from": (from_header or "")[:120],
        "subject": (subject or "")[:120],
        "url_domains": [d.lower() for d in (url_domains or [])[:5]],
        "degraded": degraded,
    }
    try:
        _EMAIL_HISTORY.parent.mkdir(parents=True, exist_ok=True)
        with _EMAIL_HISTORY.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.warning(f"[EmailHistory] 历史落盘失败 (fail-soft): {exc}")


def query(limit: int = 20) -> List[Dict[str, Any]]:
    """最近 N 条 (新→旧)."""
    return _read_tail(max(1, min(limit, 200)))


def sender_domain_stats(domain: str, days: int = 90) -> Dict[str, Any]:
    """同发件域近 N 天历史判定统计 — 注入 LLM 的「已验证事实」数据源.

    只扫尾部至多 200 条 (邮件研判频率下覆盖远超 90 天窗口), 不全量读.
    """
    domain = (domain or "").lower().strip()
    if not domain:
        return {"domain": "", "total": 0}
    cutoff = time.time() - days * 86400
    hits: List[Dict[str, Any]] = []
    for row in _read_tail(200):
        try:
            ts = time.mktime(time.strptime(row.get("ts", ""), "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            continue
        if ts < cutoff or row.get("sender_domain") != domain:
            continue
        hits.append(row)
    by_cls: Dict[str, int] = {}
    for h in hits:
        by_cls[h.get("classification", "?")] = by_cls.get(h.get("classification", "?"), 0) + 1
    return {
        "domain": domain,
        "total": len(hits),
        "by_classification": by_cls,
        "last_ts": hits[0].get("ts", "") if hits else "",
        "last_phishing_type": hits[0].get("phishing_type", "") if hits else "",
    }
