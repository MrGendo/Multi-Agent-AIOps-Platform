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

MITRE_SOURCE = "mitre_attack"

# 常用技术的英文名查询提示 (提升向量相似度命中; 未列出的 tid 走通用查询词)
_QUERY_HINTS = {
    "T1110": "Brute Force password guessing",
    "T1110.001": "Password Guessing",
    "T1110.003": "Password Spraying",
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1190": "Exploit Public-Facing Application",
    "T1046": "Network Service Discovery scanning",
    "T1041": "Exfiltration Over C2 Channel",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1068": "Exploitation for Privilege Escalation",
    "T1204": "User Execution",
    "T1583": "Acquire Infrastructure",
    "T1059": "Command and Scripting Interpreter",
    "T1071": "Application Layer Protocol C2",
}


def _query_hint(tid: str) -> str:
    return _QUERY_HINTS.get(tid, "attack technique detection mitigation")

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
                # security 研判记录 + disposition 处置登记 (反哺上下文用)
                if rec.get("alert", {}).get("kind") == "security" or rec.get("kind") == "disposition":
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


def recall_mitre_details(technique_ids: List[str], k_per_tech: int = 4) -> str:
    """按 MITRE 技术 ID 检索知识库中的技术详情 (source=mitre_attack), fail-soft.

    让 Analyst 拿到官方检测建议/缓解措施上下文, 而不是裸 ID 列表.
    k_per_tech=4: 每技术按章节切分约 5-7 chunks (标题/战术/描述/检测/缓解),
    取 4 保证覆盖检测建议与缓解措施段.
    """
    if not technique_ids:
        return ""
    try:
        if get_vector_store is None:
            return ""
        vs = get_vector_store()
        blocks = []
        for tid in technique_ids[:6]:  # 上限 6 个技术防 prompt 膨胀
            docs: list = []
            # 注意: collection schema 由历史首批语料建表, 无 tid 字段
            # (新元数据键被 milvus 静默丢弃), 不能用 expr 按 tid 过滤 —
            # 统一走 source 过滤 + 客户端按 chunk 开头 "# {tid} " 精确匹配
            try:
                # chunk 正文带 "[章/节] " 前缀 (splitter 注入), 首块形如
                # "[T1110 Brute Force / 战术] # T1110 Brute Force..."
                # 用 metadata.chapter 前缀 (== tid + 空格 + 技术名) 精确定位
                candidates = vs.similarity_search(
                    f"{tid} {_query_hint(tid)}",
                    k=30,
                    expr=f"source == '{MITRE_SOURCE}'",
                )
                docs = [
                    d for d in candidates
                    if str((d.metadata or {}).get("chapter") or "").startswith(f"{tid} ")
                ][:k_per_tech]
            except Exception:
                docs = []
            for d in docs:
                content = d.page_content.strip()
                # 截到检测建议+缓解 (描述太长, 检测/缓解才是研判要的)
                blocks.append(f"- {content[:600]}")
        if not blocks:
            return ""
        return (
            "**MITRE ATT&CK 技术详情 (知识库检索, 官方检测/缓解参考):**\n"
            + "\n".join(blocks)
        )
    except Exception as exc:
        logger.debug(f"[SecContext] MITRE 详情检索失败 (fail-soft): {exc}")
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
    # 人工处置登记 (kind=disposition) 按 session_id 关联到研判记录:
    # 人的「误报/已处置」反馈是最强的纠偏信号, 必须进 Analyst 上下文
    disp_by_session: Dict[str, str] = {}
    for rec in history:
        if rec.get("kind") == "disposition":
            act = (rec.get("disposition") or {}).get("action", "")
            if act:
                disp_by_session[rec.get("session_id", "")] = act

    for ip in ips:
        verdicts: List[str] = []
        disp_actions: List[str] = []
        for rec in history:
            alert = rec.get("alert", {})
            # 匹配: 告警 query 或 src_ip 字段含该 IP
            if ip in (rec.get("query") or "") or ip == alert.get("src_ip"):
                v = rec.get("verdict")
                if v:
                    verdicts.append(v)
                act = disp_by_session.get(rec.get("session_id", ""))
                if act:
                    disp_actions.append(act)
        if not verdicts:
            continue
        counts: Dict[str, int] = {}
        for v in verdicts:
            counts[v] = counts.get(v, 0) + 1
        summary = ", ".join(f"{k} x{cnt}" for k, cnt in sorted(counts.items()))
        disp_summary = ""
        if disp_actions:
            dcounts: Dict[str, int] = {}
            for a in disp_actions:
                dcounts[a] = dcounts.get(a, 0) + 1
            disp_txt = ", ".join(
                f"{'人工标记误报' if a == 'false_positive' else '人工已处置' if a == 'resolved' else '人工搁置'} x{c}"
                for a, c in sorted(dcounts.items())
            )
            disp_summary = f"; 其中 {disp_txt}"
        lines.append(f"- {ip}: {len(verdicts)} 次历史研判 ({summary}{disp_summary})")

    if not lines:
        return ""

    return (
        "**PRIOR TRIAGE HISTORY (含人工处置反馈, 仅供参考, 不是 disposition):**\n"
        + "\n".join(lines)
        + "\n纪律: 先前 benign 不是降低排查力度的理由, 先前 malicious 也不能作为本次定罪的证据 — "
        "人工误报标记表示「上次疑似攻击被人工排除」, 提示优先核对同类误报特征, 但仍须本次证据独立确认 — "
        "你必须基于本次告警自己的证据独立研判 (历史只影响你先看哪里)."
    )
