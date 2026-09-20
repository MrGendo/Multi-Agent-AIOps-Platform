"""历史研判记录管理 — 统计 + 策略化清理 (防只增不减堆积).

三类存储:
  1. alert_history.jsonl  研判历史 (Analyst 上下文源: 同源 IP 统计/经验召回的地面数据)
  2. secops_sessions/     研判对话会话
  3. secops_correlation/  关联研判会话

清理策略 (per 类别):
  - keep_days: 保留最近 N 天
  - keep_last: 保留最近 N 条 (与 keep_days 同给取交集更严者)
  - history 特有 keep_disposition=True: 带 disposition (人工处置登记) 的行永不清理
    — 人的反馈是最贵的训练信号, Analyst 上下文依赖它
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List

from loguru import logger

from app.security import correlation as corr
from app.security import dialogue as dlg

_DATA_DIR = Path(__file__).resolve().parents[2] / "data"
HISTORY_FILE = _DATA_DIR / "alert_history.jsonl"


def _dir_stats(d: Path) -> Dict[str, Any]:
    files = list(d.glob("*.json")) if d.exists() else []
    sizes = [f.stat().st_size for f in files]
    mtimes = [f.stat().st_mtime for f in files]
    return {
        "count": len(files),
        "size_bytes": sum(sizes),
        "oldest_ts": int(min(mtimes)) if mtimes else None,
        "newest_ts": int(max(mtimes)) if mtimes else None,
    }


def get_stats() -> Dict[str, Any]:
    """三类存储的统计 (条数/体积/最旧最新时间)."""
    return {
        "history": _file_stats(HISTORY_FILE),
        "dialogue": _dir_stats(dlg.SESSIONS_DIR),
        "correlation": _dir_stats(corr.CORRELATION_DIR),
        "now_ts": int(time.time()),
    }


def _file_stats(f: Path) -> Dict[str, Any]:
    if not f.exists():
        return {"count": 0, "size_bytes": 0, "oldest_ts": None, "newest_ts": None}
    lines = [l for l in f.read_text(encoding="utf-8").splitlines() if l.strip()]
    oldest = newest = None
    for l in lines:
        try:
            rec = json.loads(l)
            ts = rec.get("finished_at") or rec.get("ts") or ""
            if ts:
                t = int(time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))) if "T" in ts else None
                if t:
                    oldest = t if oldest is None else min(oldest, t)
                    newest = t if newest is None else max(newest, t)
        except Exception:
            continue
    return {
        "count": len(lines),
        "size_bytes": f.stat().st_size,
        "oldest_ts": oldest,
        "newest_ts": newest,
    }


def _purge_dir(d: Path, keep_days: int = 0, keep_last: int = 0) -> int:
    """按时间/条数清理目录下的会话 json, 返回删除数."""
    if not d.exists():
        return 0
    files = sorted(d.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)  # 新→旧
    cutoff = time.time() - keep_days * 86400 if keep_days > 0 else None
    deleted = 0
    for idx, f in enumerate(files):
        if keep_last > 0 and idx < keep_last:
            continue  # 保留最近 N 条
        if cutoff and f.stat().st_mtime >= cutoff:
            continue  # 在保留期内
        try:
            f.unlink()
            deleted += 1
        except Exception as exc:
            logger.warning(f"[HistoryMgmt] 删除会话文件失败 {f.name}: {exc}")
    return deleted


def purge(
    *,
    targets: List[str],
    keep_days: int = 0,
    keep_last: int = 0,
    keep_disposition: bool = True,
) -> Dict[str, Any]:
    """执行清理. targets ∈ {history, dialogue, correlation}. 返回各类删除数.

    keep_days/keep_last 为 0 表示该维度不限 (但至少一维 >0 才会删东西,
    双 0 时 history 仍可清无 disposition 行 — 显式调用即意图).
    """
    result: Dict[str, Any] = {"deleted": {}}
    if "dialogue" in targets:
        result["deleted"]["dialogue"] = _purge_dir(dlg.SESSIONS_DIR, keep_days, keep_last)
        # 内存注册表同步丢弃已删会话
        for sid in list(dlg._sessions.keys()):
            if not (dlg.SESSIONS_DIR / f"{sid}.json").exists():
                dlg._sessions.pop(sid, None)
    if "correlation" in targets:
        result["deleted"]["correlation"] = _purge_dir(corr.CORRELATION_DIR, keep_days, keep_last)
        for cid in list(corr._sessions.keys()):
            if not (corr.CORRELATION_DIR / f"{cid}.json").exists():
                corr._sessions.pop(cid, None)
    if "history" in targets:
        result["deleted"]["history"] = _purge_history_file(keep_days, keep_last, keep_disposition)
    result["stats_after"] = get_stats()
    logger.info(f"[HistoryMgmt] 清理完成: {result['deleted']}")
    return result


def _purge_history_file(keep_days: int, keep_last: int, keep_disposition: bool) -> int:
    """清 alert_history.jsonl (保留 disposition 行可选). 返回删除行数."""
    if not HISTORY_FILE.exists():
        return 0
    lines = [l for l in HISTORY_FILE.read_text(encoding="utf-8").splitlines() if l.strip()]
    cutoff = time.time() - keep_days * 86400 if keep_days > 0 else None

    def _row_ts(rec: dict) -> float:
        ts = rec.get("finished_at") or rec.get("ts") or ""
        try:
            return time.mktime(time.strptime(str(ts)[:19], "%Y-%m-%dT%H:%M:%S")) if "T" in str(ts) else 0.0
        except Exception:
            return 0.0

    keep: List[str] = []
    # 倒序 (新→旧) 应用 keep_last
    indexed = list(reversed(lines))
    kept_recent = 0
    for l in indexed:
        try:
            rec = json.loads(l)
        except Exception:
            keep.append(l)  # 损坏行不丢, 保守
            continue
        if keep_disposition and rec.get("disposition"):
            keep.append(l)  # 人工处置登记永保留
            continue
        if keep_last > 0 and kept_recent < keep_last:
            keep.append(l)
            kept_recent += 1
            continue
        if cutoff and _row_ts(rec) >= cutoff:
            keep.append(l)  # 保留期内
            continue
        if keep_days == 0 and keep_last == 0 and not keep_disposition:
            continue  # 双 0 且不保护 disposition = 全清 (显式意图)
        if keep_days > 0 or keep_last > 0:
            continue  # 已过保留期/额度的行 → 删
        # 双 0 + keep_disposition=True: 只清无 disposition 的行
    deleted = len(lines) - len(keep)
    if deleted > 0:
        HISTORY_FILE.write_text("\n".join(reversed(keep)) + "\n", encoding="utf-8")
    return deleted
