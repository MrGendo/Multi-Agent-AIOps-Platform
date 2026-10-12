"""传感器覆盖自监 (Coverage Watch) — 防御的防御.

资产拓扑说某资产该被 WAF/HIDS/NDR 罩着, 但最近窗口内该传感器对它
零事件 → 传感器可能断流/离线/被绕过. 这类「该报没报」是 SOC 最隐蔽
的盲区: 攻击正在发生而传感器瞎了, 没有任何告警会提醒你.

实现: 纯查询端点 (GET /api/v1/secops/coverage), 由人/定时器调用 —
不做后台守护 (个人项目没有常驻场景, 定时触发即可), 对现有功能零影响.

时效判断: 最近 N 分钟 (默认 30) alert_history.jsonl 里出现过的
source 视为「该传感器近期有事件」. 注意这是粗粒度信号:
- 以「传感器全局是否有事件」近似「对具体资产是否有事件」(历史里
  无资产-传感器映射, 拿得到的是 source 维度)
- 结论是「疑似」而非「确诊」: 断流/静默正常期/资产刚接入都会触发
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List

from loguru import logger

from app.security.asset_graph import _load_topology

_HISTORY_FILE = Path(__file__).resolve().parents[2] / "data" / "alert_history.jsonl"

# source 字段 → 拓扑传感器的映射 (webhook 侧 source 命名)
_SOURCE_TO_SENSOR: Dict[str, str] = {
    "safeline": "waf",
    "wazuh": "hids",
    "cef": "ndr",
    "suricata": "ids",
    "falco": "hids",
    "generic": "*",  # 通用 schema 无法归到具体传感器
}


def _recent_sources(window_min: int = 30) -> Dict[str, float]:
    """最近窗口内出现过的 source → 最后事件时间戳 (epoch)."""
    cutoff = time.time() - window_min * 60
    seen: Dict[str, float] = {}
    try:
        if not _HISTORY_FILE.exists():
            return seen
        # 倒序扫最近 300 行 (性能: 不全量翻档)
        lines = _HISTORY_FILE.read_text(encoding="utf-8").splitlines()[-300:]
        for line in lines:
            try:
                rec = json.loads(line)
            except Exception:
                continue
            src = (rec.get("alert") or {}).get("source") or ""
            if not src:
                continue
            ts = rec.get("finished_at") or ""
            try:
                t = time.mktime(time.strptime(str(ts)[:19], "%Y-%m-%dT%H:%M:%S")) if "T" in str(ts) else 0
            except Exception:
                t = 0
            if t >= cutoff:
                seen[src] = max(seen.get(src, 0), t)
    except Exception as exc:
        logger.debug(f"[CoverageWatch] 历史扫描失败 (fail-soft): {exc}")
    return seen


def coverage_report(window_min: int = 30) -> Dict[str, Any]:
    """覆盖自监报告: 每传感器 静默时长/覆盖资产数/疑似断流判定."""
    topo = _load_topology()
    assets = topo.get("assets") or []
    if not assets:
        return {"status": "no_topology", "message": "无资产拓扑 (data/assets.yaml), 覆盖自监不可用", "sensors": []}

    recent = _recent_sources(window_min)
    recent_sensors = set()
    for src in recent:
        s = _SOURCE_TO_SENSOR.get(src)
        if s and s != "*":
            recent_sensors.add(s)

    # 传感器维度: 拓扑里被引用的传感器 + 覆盖资产数
    sensor_assets: Dict[str, List[str]] = {}
    for a in assets:
        for s in a.get("sensors") or []:
            sensor_assets.setdefault(str(s), []).append(str(a.get("id")))

    sensors_out: List[Dict[str, Any]] = []
    for s, covered in sorted(sensor_assets.items()):
        has_events = s in recent_sensors
        sensors_out.append({
            "sensor": s,
            "covered_assets": len(covered),
            "assets_sample": covered[:5],
            "recent_events": has_events,
            "status": "ok" if has_events else "silent",
            "note": "" if has_events else f"最近 {window_min} 分钟零事件 — 疑似断流/离线 (或该时段确无活动, 需人工确认)",
        })

    silent = [s["sensor"] for s in sensors_out if s["status"] == "silent"]
    return {
        "status": "ok" if not silent else "gaps",
        "window_min": window_min,
        "silent_sensors": silent,
        "message": (
            "全部传感器近期有事件" if not silent
            else f"{len(silent)} 个传感器静默: {', '.join(silent)} — 该报没报是盲区, 建议核查设备状态"
        ),
        "sensors": sensors_out,
    }
