"""Suricata EVE 告警搬运器 — tail eve.json, 只把 alert 事件转发到平台.

适用于无法给 Suricata 配 webhook 的环境 (本机无 Docker/filebeat 时最简方案).
幂等: 记录已读文件偏移 (data/.suricata_tailer.offset), 重启不重发.

用法:
    .venv/bin/python scripts/ship_suricata_alerts.py --eve /var/log/suricata/eve.json
    # 干跑 (只打印不发送):
    .venv/bin/python scripts/ship_suricata_alerts.py --eve ... --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path

import httpx

DEFAULT_WEBHOOK = "http://127.0.0.1:9900/api/v1/webhook/security"
OFFSET_SUFFIX = ".offset"


async def ship(eve_path: Path, webhook: str, dry_run: bool = False) -> None:
    offset_file = eve_path.with_name(eve_path.name + OFFSET_SUFFIX)
    offset = 0
    if offset_file.exists():
        try:
            offset = int(offset_file.read_text().strip() or 0)
        except ValueError:
            offset = 0

    print(f"[ship-suricata] tail {eve_path} @ offset={offset} -> {webhook}")
    sent = 0
    async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
        with eve_path.open("r", encoding="utf-8", errors="replace") as f:
            f.seek(offset)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue  # 半行 (写入中) 或脏行, 跳过
                if ev.get("event_type") != "alert":
                    continue
                if dry_run:
                    print(f"[dry-run] would ship: {ev.get('alert', {}).get('signature', '?')[:60]}")
                    sent += 1
                    continue
                try:
                    resp = await client.post(webhook, json=ev)
                    ok = resp.status_code == 200
                    print(f"[ship] {resp.status_code} {ev.get('alert', {}).get('signature', '?')[:60]}")
                    sent += 1 if ok else 0
                except Exception as exc:
                    print(f"[ship] 失败 (偏移不推进, 重启后重试): {exc}")
                    return  # 失败即停, 不推进 offset, 防丢告警
            new_offset = f.tell()

    if not dry_run and new_offset > offset:
        offset_file.write_text(str(new_offset))
    print(f"[ship-suricata] 完成: 发送 {sent} 条, offset {offset} -> {new_offset}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eve", required=True, help="Suricata eve.json 路径")
    parser.add_argument("--webhook", default=DEFAULT_WEBHOOK, help="平台 webhook 地址")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--loop", action="store_true", help="持续轮询模式 (每 5s)")
    args = parser.parse_args()

    eve = Path(args.eve)
    if not eve.exists():
        raise SystemExit(f"eve.json 不存在: {eve}")
    if args.loop:
        while True:
            asyncio.run(ship(eve, args.webhook, args.dry_run))
            time.sleep(5)
    else:
        asyncio.run(ship(eve, args.webhook, args.dry_run))


if __name__ == "__main__":
    main()
