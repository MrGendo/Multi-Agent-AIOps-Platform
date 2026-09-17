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

from app.security.consolidation import SECOPS_EXP_SOURCE

try:
    from app.core.vector_store import get_vector_store
except Exception:  # 演示环境无 Milvus 时导入即降级
    get_vector_store = None  # type: ignore[assignment]

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


def recall_similar_patterns(query: str, k: int = 2) -> str:
    """向量召回同类告警的历史研判经验 (source=secops_experience), fail-soft.

    返回格式化的经验块供 Analyst 参考; 无库/无命中/异常 → 空串.
    纪律同 build_prior_history_context: 召回结果是「当时证据下的结论」,
    不是本次定罪依据.
    """
    try:
        if get_vector_store is None:
            return ""
        vs = get_vector_store()
        docs = vs.similarity_search(query, k=k, expr=f"source == '{SECOPS_EXP_SOURCE}'")
        if not docs:
            return ""
        blocks = []
        for d in docs:
            title = (d.metadata or {}).get("h1") or "历史研判"
            verdict = (d.metadata or {}).get("verdict") or ""
            verdict_tag = f" [当时判定: {verdict}]" if verdict else ""
            blocks.append(f"- {title}{verdict_tag}: {d.page_content[:300]}")
        logger.info(f"[SecContext] 经验召回命中 {len(docs)} 条同类研判 (供 Analyst 参考)")
        return (
            "**SIMILAR THREAT PATTERNS (向量召回的历史研判经验, 仅供参考):**\n"
            + "\n".join(blocks)
            + "\n纪律: 这些是历史告警在当时证据下的结论, 不是本次告警的证据 — "
            "可参考其判定逻辑与关注点, 不得直接复用其 verdict."
        )
    except Exception as exc:
        logger.debug(f"[SecContext] 经验召回失败 (fail-soft): {exc}")
        return ""


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
