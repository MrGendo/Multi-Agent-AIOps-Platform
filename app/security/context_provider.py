"""SecOps 研判上下文供给器 (借鉴 AI_SOC context_manager 三层设计).

从本地研判历史 (data/alert_history.jsonl) 构建两层上下文注入 Analyst prompt:
  1. Prior triage history — 同源 IP 的历史研判 verdict 统计
  2. (预留) environment context — 组织静态知识, 走 settings

纪律 (借鉴 Vigil memory 语义):
  - 历史 verdict 不是 disposition: 先前 benign 不是少查的理由,
    先前 malicious 也不是新告警定罪的证据 (recall never corroborates)
  - 全部 fail-soft: 读不到/解析失败 → 空字符串, 绝不阻塞研判
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from loguru import logger

# 历史文件位置 (与 webhook 落盘同源)
_HISTORY_FILE = Path(__file__).resolve().parents[2] / "data" / "alert_history.jsonl"

# 注入 prompt 的上限 (防 prompt 膨胀)
_MAX_HISTORY_RECORDS = 200
_MAX_IPS_PER_BLOCK = 5


def _load_security_history() -> List[Dict[str, Any]]:
    """读本地安全研判历史, fail-soft 返回列表."""
    try:
        if not _HISTORY_FILE.exists():
            return []
        records: List[Dict[str, Any]] = []
        with _HISTORY_FILE.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if rec.get("alert", {}).get("kind") == "security":
                    records.append(rec)
        return records[-_MAX_HISTORY_RECORDS:]
    except Exception as exc:
        logger.debug(f"[SecContext] 研判历史读取失败 (fail-soft): {exc}")
        return []


def build_prior_history_context(iocs: Dict[str, List[str]]) -> str:
    """构建同源 IP 的历史研判统计块, 无数据返回空串.

    只统计 verdict (不给旧报告原文 — 旧结论可能基于当时的证据,
    塞原文会诱导 Analyst 复述而不是独立研判).
    """
    ips = [ip for ip in (iocs.get("ips") or [])][:_MAX_IPS_PER_BLOCK]
    if not ips:
        return ""

    history = _load_security_history()
    if not history:
        return ""

    lines: List[str] = []
    for ip in ips:
        verdicts: List[str] = []
        for rec in history:
            alert = rec.get("alert", {})
            # 匹配: 告警 query 或 src_ip 字段含该 IP
            if ip in (rec.get("query") or "") or ip == alert.get("src_ip"):
                v = rec.get("verdict")
                if v:
                    verdicts.append(v)
        if not verdicts:
            continue
        counts: Dict[str, int] = {}
        for v in verdicts:
            counts[v] = counts.get(v, 0) + 1
        summary = ", ".join(f"{k} x{cnt}" for k, cnt in sorted(counts.items()))
        lines.append(f"- {ip}: {len(verdicts)} 次历史研判 ({summary})")

    if not lines:
        return ""

    return (
        "**PRIOR TRIAGE HISTORY (仅供参考, 不是 disposition):**\n"
        + "\n".join(lines)
        + "\n纪律: 先前 benign 不是降低排查力度的理由, 先前 malicious 也不能作为本次定罪的证据 — "
        "你必须基于本次告警自己的证据独立研判 (历史只影响你先看哪里)."
    )
