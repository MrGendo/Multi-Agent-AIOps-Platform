"""判定回归 (Judgment Regression) — 用历史告警 golden set 量化判定漂移.

动机: 模型升级/prompt 改动后, 研判质量会不会漂移没人知道. 借 CI 回归
思想: 固定一组历史告警 (golden set + 当时判定), 用廉价通道重放, 报告
verdict 一致率 — 判定质量的「测试套件」.

约束: 独立脚本性质 (scripts/judgment_regression.py 调用), 不挂任何
运行时路径, 对现有功能零影响. golden set 存 data/golden_set.jsonl.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from loguru import logger

_GOLDEN_FILE = Path(__file__).resolve().parents[2] / "data" / "golden_set.jsonl"

# verdict 相似度分组: 同组视为「一致」(suspicious↔inconclusive 都是未定论,
# 严格相等太苛刻; malicious↔benign 是实质翻转)
_EQUIV_GROUPS = [
    {"suspicious", "inconclusive"},
]


def _verdict_agree(a: str, b: str) -> bool:
    if a == b:
        return True
    for g in _EQUIV_GROUPS:
        if a in g and b in g:
            return True
    return False


def load_golden_set() -> List[Dict[str, Any]]:
    """读 golden set (data/golden_set.jsonl, 一行一个 {query, verdict, note})."""
    try:
        if not _GOLDEN_FILE.exists():
            return []
        rows = []
        for line in _GOLDEN_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if rec.get("query") and rec.get("verdict"):
                    rows.append(rec)
            except Exception:
                continue
        return rows
    except Exception as exc:
        logger.debug(f"[JudgmentReg] golden set 读取失败: {exc}")
        return []


def build_golden_set_from_history(limit: int = 20) -> List[Dict[str, Any]]:
    """从 alert_history.jsonl 抽取 golden set 候选 (人审后写入 golden_set.jsonl).

    抽取规则: security 域 + 有 verdict + query 长度适中 (太短无研判价值).
    只生成候选文件, 不自动生效 — golden set 必须人审 (回归基线本身错了
    会把系统带回沟里).
    """
    hist = Path(__file__).resolve().parents[2] / "data" / "alert_history.jsonl"
    out: List[Dict[str, Any]] = []
    try:
        if not hist.exists():
            return out
        seen_query = set()
        for line in hist.read_text(encoding="utf-8").splitlines():
            if len(out) >= limit:
                break
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if (rec.get("alert") or {}).get("kind") != "security":
                continue
            q, v = rec.get("query") or "", rec.get("verdict") or ""
            if not q or not v or len(q) < 30 or len(q) > 1500 or q in seen_query:
                continue
            seen_query.add(q)
            out.append({"query": q, "verdict": v, "note": "auto-candidate-需人审"})
        return out
    except Exception as exc:
        logger.debug(f"[JudgmentReg] 历史抽取失败: {exc}")
        return out


def score_replay(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """对重放结果打分: verdict 一致率 + 翻转清单.

    results: [{query, expected, actual}] — 实际重放由 scripts 侧跑
    (廉价通道), 本函数只做纯计算 (可单测).
    """
    if not results:
        return {"total": 0, "agree": 0, "agree_rate": 0.0, "flips": []}
    agree = 0
    flips: List[Dict[str, str]] = []
    for r in results:
        exp, act = r.get("expected", ""), r.get("actual", "")
        if _verdict_agree(exp, act):
            agree += 1
        else:
            flips.append({"query": r.get("query", "")[:120], "expected": exp, "actual": act})
    rate = agree / len(results)
    verdict = "PASS" if rate >= 0.9 else ("WARN" if rate >= 0.75 else "FAIL")
    return {
        "total": len(results),
        "agree": agree,
        "agree_rate": round(rate, 3),
        "grade": verdict,
        "flips": flips,
    }
