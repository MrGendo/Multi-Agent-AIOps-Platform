"""威胁情报富化 + MITRE ATT&CK 映射.

enrich_iocs: 对告警 IOC 逐个查外部威胁情报 (走 app.core.web_search 的
provider 调度), fail-soft — 无 key/网络失败/超时一律降级为空列表, 绝不阻塞研判.

map_mitre: alert_type 静态映射 + 证据文本中技术 ID 正则提取, 合并去重.

借鉴 SentinelOps (Tavily 情报搜索) / OpenTriage (情报仅供参考不直接定罪) 设计,
按项目风格重写. 外部情报结果仅供 Analyst 参考, 不作为定罪依据.
"""

from __future__ import annotations

import re
from typing import Dict, List

from loguru import logger

from app.core.web_search import search as web_search

# 单告警情报查询上限 (防 token 爆炸; SentinelOps 无上限, 我们加了硬顶)
MAX_INTEL_QUERIES = 8

# IOC 查询优先级: CVE > hash > IP > 域名 (信息增益大的优先)
_IOC_PRIORITY = ("cves", "hashes", "ips", "domains")

# alert_type → MITRE ATT&CK 技术 ID 静态映射 (官方 Enterprise 矩阵)
_MITRE_BY_ALERT_TYPE: Dict[str, List[str]] = {
    "brute_force": ["T1110"],
    "malware": ["T1204", "T1583"],
    "network_scan": ["T1046"],
    "data_exfiltration": ["T1041"],
    "privilege_escalation": ["T1548", "T1068"],
    "phishing": ["T1566"],
    "web_attack": ["T1190"],
    "anomaly": [],
    "unknown": [],
}

_MITRE_ID = re.compile(r"\bT\d{4}\b")


def _pick_query_targets(iocs: Dict[str, List[str]], limit: int) -> List[str]:
    """按优先级选出情报查询目标 (去重, 截断到 limit)."""
    targets: List[str] = []
    for kind in _IOC_PRIORITY:
        for item in iocs.get(kind, []) or []:
            if item and item not in targets:
                targets.append(item)
                if len(targets) >= limit:
                    return targets
    return targets


async def enrich_iocs(iocs: Dict[str, List[str]], max_per_query: int = 2) -> List[str]:
    """对 IOC 查询外部威胁情报, 返回片段列表.

    Args:
        iocs: extract_iocs 的产出
        max_per_query: 每个指标最多取几条结果

    Returns:
        片段列表, 每条格式 '[{indicator}] {content} (source: {url})';
        无可用 provider/失败/超时 → 空列表 (fail-soft, 不抛异常).
    """
    targets = _pick_query_targets(iocs, MAX_INTEL_QUERIES)
    if not targets:
        return []

    snippets: List[str] = []
    for indicator in targets:
        try:
            results = web_search(
                f"threat intelligence {indicator}", max_results=max_per_query
            )
            for r in results or []:
                content = (r.get("snippet") or "").strip()
                url = r.get("url", "")
                if content:
                    snippets.append(f"[{indicator}] {content[:300]} (source: {url})")
        except Exception as exc:  # fail-soft: 单个指标失败不影响其余
            logger.warning(f"[ThreatIntel] 情报查询失败 {indicator}: {exc}")
            continue
    return snippets


def map_mitre(alert_type: str, evidence_text: str = "") -> List[str]:
    """alert_type 静态映射 + 证据文本技术 ID 提取, 合并去重 (保序)."""
    mapped: List[str] = []
    for tid in _MITRE_BY_ALERT_TYPE.get((alert_type or "").strip().lower(), []):
        if tid not in mapped:
            mapped.append(tid)
    for tid in _MITRE_ID.findall(evidence_text or ""):
        tid = tid.upper()
        if tid not in mapped:
            mapped.append(tid)
    return mapped
