"""研判置信度校准 (Confidence Calibration) — 用「后来的真相」验证自评置信度.

动机: Analyst 置信度是 LLM 自评 (0.72 和 0.85 有什么区别没人知道).
人工处置登记 (disposition: resolved / false_positive) 是唯一带「人的
最终结论」的信号 — 把它与研判时的自评置信度 join 起来, 就能量化回答
「模型说 80% 确信时, 实际有多大比例是真的」.

方法 (经典校准度量, 全部在历史 jsonl 上离线计算, 纯只读零影响):
  - 分桶 reliability: 置信度分桶后, 桶内实际恶意率 vs 平均自评置信度
  - ECE (Expected Calibration Error): Σ 桶权重 × |实际率 - 平均置信|
  - Brier score: (置信 - 真值)² 的均值 (0=完美, 越小越好)
  - verdict × disposition 一致性矩阵: 系统判定 vs 人工处置的混淆表

真值口径 (y ∈ {0,1}):
  - false_positive → 0 (人工认定不是威胁)
  - resolved → 1 (人工认定是真实威胁且已处置)
  - deferred → 不计 (人也没结论, 无真值)

约束:
  - 无配对样本时诚实返回 insufficient_data, 不编造度量
  - 置信度缺失的旧记录跳过 (断线补齐前落盘的记录, 见 join 键说明)
  - 全部 fail-soft: 历史文件读不到 → 空结果
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from loguru import logger

_HISTORY_FILE = Path(__file__).resolve().parents[2] / "data" / "alert_history.jsonl"

# 置信度分桶边界 (0.0-1.0 十等分, 统一左闭右开, 最后桶闭区间)
_BUCKET_EDGES = [i / 10 for i in range(11)]

# disposition → 真值 (deferred 无真值不进校准)
_ACTION_TO_LABEL = {"false_positive": 0, "resolved": 1}


def _load_pairs() -> List[Tuple[float, int, str, str]]:
    """扫描历史, 返回 (自评置信度, 真值, verdict, session_id) 配对列表.

    join 规则: disposition 行按 session_id 关联回研判记录 (含 dlg- 前缀
    兼容 — 处置登记可能拿对话会话 id, 研判记录是原始 triage id).
    """
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
                    records.append(json.loads(line))
                except Exception:
                    continue

        # 研判记录: kind=security 的行带 verdict/confidence (新记录才有
        # confidence, 旧记录缺键跳过 — 校准样本必须两段都有)
        triage_by_sid: Dict[str, Dict[str, Any]] = {}
        for rec in records:
            if (rec.get("alert") or {}).get("kind") == "security":
                sid = rec.get("session_id", "")
                if sid:
                    triage_by_sid[sid] = rec

        pairs: List[Tuple[float, int, str, str]] = []
        for rec in records:
            if rec.get("kind") != "disposition":
                continue
            action = (rec.get("disposition") or {}).get("action", "")
            label = _ACTION_TO_LABEL.get(action)
            if label is None:
                continue
            sid = rec.get("session_id", "")
            # dlg- 前缀剥掉回原始研判 id; 关联会话 (corr-) 也有 report_verdict
            base_sid = sid[4:] if sid.startswith("dlg-") else sid
            tri = triage_by_sid.get(sid) or triage_by_sid.get(base_sid)
            if not tri:
                continue
            conf = tri.get("confidence")
            verdict = tri.get("verdict") or ""
            if conf is None:
                continue
            try:
                pairs.append((max(0.0, min(1.0, float(conf))), label, verdict, sid))
            except (TypeError, ValueError):
                continue
        return pairs
    except Exception as exc:
        logger.debug(f"[Calibration] 历史扫描失败 (fail-soft): {exc}")
        return []


def _bucket_of(conf: float) -> int:
    """置信度 → 桶下标 (0-9)."""
    for i in range(10):
        lo, hi = _BUCKET_EDGES[i], _BUCKET_EDGES[i + 1]
        if lo <= conf < hi or (i == 9 and conf == 1.0):
            return i
    return 0


def calibration_report() -> Dict[str, Any]:
    """置信度校准报告 (纯只读). 样本不足时返回 insufficient_data."""
    pairs = _load_pairs()
    n = len(pairs)
    if n == 0:
        return {
            "status": "insufficient_data",
            "message": (
                "暂无可校准样本 — 需要「研判时置信度 + 人工处置登记」配对. "
                "在研判工作台对历史研判登记处置 (误报/已处置) 即积累样本."
            ),
            "sample_count": 0,
        }

    # ---- 分桶 reliability ----
    buckets: List[Dict[str, Any]] = []
    ece = 0.0
    for i in range(10):
        members = [p for p in pairs if _bucket_of(p[0]) == i]
        if not members:
            continue
        size = len(members)
        avg_conf = sum(p[0] for p in members) / size
        actual_rate = sum(p[1] for p in members) / size
        gap = abs(avg_conf - actual_rate)
        ece += (size / n) * gap
        buckets.append({
            "bucket": f"{_BUCKET_EDGES[i]:.1f}-{_BUCKET_EDGES[i + 1]:.1f}",
            "count": size,
            "avg_confidence": round(avg_conf, 4),
            "actual_positive_rate": round(actual_rate, 4),
            "gap": round(gap, 4),
            "direction": (
                "overconfident" if avg_conf > actual_rate + 0.05
                else "underconfident" if actual_rate > avg_conf + 0.05
                else "calibrated"
            ),
        })

    # ---- Brier score ----
    brier = sum((conf - label) ** 2 for conf, label, _, _ in pairs) / n

    # ---- verdict × disposition 一致性 ----
    matrix: Dict[str, Dict[str, int]] = {}
    for _, label, verdict, _ in pairs:
        action = "resolved" if label == 1 else "false_positive"
        row = matrix.setdefault(verdict or "unknown", {"resolved": 0, "false_positive": 0})
        row[action] += 1

    # 误报率: 系统判恶意类 (malicious/suspicious) 却被人工标 false_positive
    threat_like = [p for p in pairs if p[2] in ("malicious", "suspicious")]
    fp_of_threat = sum(1 for p in threat_like if p[1] == 0)
    false_positive_rate = round(fp_of_threat / len(threat_like), 4) if threat_like else None

    return {
        "status": "ok",
        "sample_count": n,
        "metrics": {
            "ece": round(ece, 4),
            "brier": round(brier, 4),
            "brier_skill_vs_always_05": round(0.25 - brier, 4),
            "false_positive_rate_of_threat_verdicts": false_positive_rate,
        },
        "reliability_buckets": buckets,
        "verdict_disposition_matrix": matrix,
        "reading_guide": (
            "ECE=0 表示完全校准; 桶内 avg_confidence 与 actual_positive_rate 差 "
            ">0.05 记 overconfident/underconfident. 样本 <30 时结论仅供参考, "
            "数字会随处置登记积累稳定下来."
        ),
    }
