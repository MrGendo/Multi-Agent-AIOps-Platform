"""长亭雷池 (SafeLine) 攻击事件拉取器 — 定时轮询开放 API 并转发研判.

雷池社区版无原生 webhook, 用开放 API 拉模式:
  GET {SAFELINE_URL}/api/open/events?page=1&page_size=20
  Header: X-Api-Token: {SAFELINE_API_TOKEN}

幂等: 记录已见事件 id (data/.safeline_seen.json, 超出窗口自动清理),
重复事件不重发. 官方 API 定义: chaitin/SafeLine mcp_server internal/api.

用法:
    export SAFELINE_URL=https://waf.example.com:9443
    export SAFELINE_API_TOKEN=xxx
    .venv/bin/python scripts/poll_safeline.py            # 单次
    .venv/bin/python scripts/poll_safeline.py --loop     # 每 30s 轮询
    .venv/bin/python scripts/poll_safeline.py --dry-run  # 只看不发
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
from pathlib import Path

import httpx

WEBHOOK = os.environ.get("SECOPS_WEBHOOK", "http://127.0.0.1:9900/api/v1/webhook/security")
SEEN_FILE = Path(__file__).resolve().parents[1] / "data" / ".safeline_seen.json"
SEEN_KEEP = 2000  # 保留最近 N 个事件 id


def _load_seen() -> set:
    try:
        return set(json.loads(SEEN_FILE.read_text()))
    except Exception:
        return set()


def _save_seen(seen: set) -> None:
    SEEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    keep = sorted(seen)[-SEEN_KEEP:]
    SEEN_FILE.write_text(json.dumps(keep))


async def poll_once(base_url: str, token: str, webhook: str, dry_run: bool = False) -> int:
    seen = _load_seen()
    sent = 0
    async with httpx.AsyncClient(timeout=30, verify=False, trust_env=False) as client:
        resp = await client.get(
            f"{base_url.rstrip('/')}/api/open/events",
            params={"page": 1, "page_size": 20},
            headers={"X-Api-Token": token},
        )
        resp.raise_for_status()
        body = resp.json()
        nodes = ((body.get("data") or {}).get("nodes")) or []
        for ev in nodes:
            eid = ev.get("id")
            if eid in seen:
                continue
            # 单条事件按雷池结构原样转发 (webhook 的 safeline 适配器识别归一)
            if dry_run:
                print(f"[dry-run] {ev.get('ip')} -> {ev.get('host')} deny={ev.get('deny_count')}")
            else:
                r = await client.post(webhook, json=ev)
                print(f"[ship] {r.status_code} {ev.get('ip')} deny={ev.get('deny_count')}")
            seen.add(eid)
            sent += 1
    _save_seen(seen)
    return sent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loop", action="store_true", help="持续轮询 (每 30s)")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--url", default=os.environ.get("SAFELINE_URL", ""), help="雷池地址")
    parser.add_argument("--token", default=os.environ.get("SAFELINE_API_TOKEN", ""))
    parser.add_argument("--interval", type=int, default=30)
    args = parser.parse_args()

    if not args.url or not args.token:
        raise SystemExit("需要 --url/--token 或环境变量 SAFELINE_URL / SAFELINE_API_TOKEN")

    if args.loop:
        while True:
            try:
                n = asyncio.run(poll_once(args.url, args.token, WEBHOOK, args.dry_run))
                if n:
                    print(f"[poll] 新事件 {n} 条已转发")
            except Exception as exc:
                print(f"[poll] 失败 (下轮重试): {exc}")
            time.sleep(args.interval)
    else:
        n = asyncio.run(poll_once(args.url, args.token, WEBHOOK, args.dry_run))
        print(f"[poll] 完成: 转发 {n} 条新事件")


if __name__ == "__main__":
    main()
