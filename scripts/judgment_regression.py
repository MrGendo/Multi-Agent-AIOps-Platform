#!/usr/bin/env python3
"""判定回归重放脚本 — golden set 重放并报告 verdict 一致率.

用法:
  # 1. 生成 golden set 候选 (从历史研判抽取, 需人审后生效)
  .venv/bin/python scripts/judgment_regression.py --build

  # 2. 重放 (默认廉价通道 qwen-plus, 避免烧主模型配额)
  .venv/bin/python scripts/judgment_regression.py --replay

  # 3. 只算分 (已有重放结果文件)
  .venv/bin/python scripts/judgment_regression.py --score replay.json

输出: 一致率 + 翻转清单 (expected vs actual) + PASS/WARN/FAIL.
纯独立脚本 — 不影响任何运行时路径.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.security.judgment_regression import (  # noqa: E402
    build_golden_set_from_history,
    load_golden_set,
    score_replay,
)

GOLDEN_PATH = Path(__file__).resolve().parents[1] / "data" / "golden_set.jsonl"


async def replay_one(query: str, model: str) -> str:
    """单条重放: 走 triage 主判定链但只要 verdict (域分类+Triage)."""
    from app.security.domain_classifier import classify_domain
    from app.security.triage import triage_node

    dom = await classify_domain(query)
    if (dom.get("domain") if isinstance(dom, dict) else getattr(dom, "domain", "")) != "security":
        return "(分流变化)"
    state = {
        "input": query,
        "iocs": {},
        "anomaly_score": 0.0,
        "loop_count": 0,
    }
    out = await triage_node(state)
    return out.get("triage_verdict") or "investigate"


async def run_replay(model: str) -> None:
    golden = load_golden_set()
    if not golden:
        print("golden set 为空 — 先 --build 生成并人审 data/golden_set.jsonl")
        return
    results = []
    for i, g in enumerate(golden):
        actual = await replay_one(g["query"], model)
        results.append({"query": g["query"], "expected": g["verdict"], "actual": actual})
        print(f"[{i+1}/{len(golden)}] expected={g['verdict']} actual={actual}")
    Path("/tmp/judgment_replay.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    report = score_replay(results)
    print(json.dumps(report, ensure_ascii=False, indent=1))
    print("重放明细: /tmp/judgment_replay.json")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", action="store_true", help="从历史生成 golden set 候选")
    ap.add_argument("--replay", action="store_true", help="重放 golden set")
    ap.add_argument("--score", type=str, default="", help="对结果文件算分")
    ap.add_argument("--model", default="qwen-plus", help="重放通道 (默认廉价 qwen-plus)")
    args = ap.parse_args()

    if args.build:
        rows = build_golden_set_from_history(limit=20)
        if not rows:
            print("历史中无可抽取候选")
            return
        with GOLDEN_PATH.open("a", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"已追加 {len(rows)} 条候选到 {GOLDEN_PATH} — 人审后生效 (删掉误抽的行)")
        return

    if args.replay:
        asyncio.run(run_replay(args.model))
        return

    if args.score:
        results = json.loads(Path(args.score).read_text(encoding="utf-8"))
        print(json.dumps(score_replay(results), ensure_ascii=False, indent=1))
        return

    ap.print_help()


if __name__ == "__main__":
    main()
