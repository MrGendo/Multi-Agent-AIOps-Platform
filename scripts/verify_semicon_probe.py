#!/usr/bin/env python3
"""半导体仿真探针确定性验证脚本.

验证 mcp_servers/semicon_server.py 的 5 个工具:
  1. 确定性: 同一 equipment_id 两次调用, 结果完全一致 (JSON 序列化相等)
  2. 阈值标记: 各故障剧本的告警标记/状态分级正确
  3. 交叉一致性: 告警列表中 SET 的 ALID 与故障剧本对应

用法: .venv/bin/python scripts/verify_semicon_probe.py
输出: 逐项 PASS/FAIL, 全部通过打印 PASS (退出码 0)
"""

import json
import sys
from pathlib import Path

# 让脚本可从任意 cwd 运行
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "mcp_servers"))

from semicon_server import (  # noqa: E402
    chamber_pressure,
    chiller_temp,
    equipment_alarm_list,
    secs_link_status,
    wafer_yield_trend,
    _fault_class,
)

# 各剧本的确定性代表设备 (由 _fault_class 哈希决定, 跨进程稳定)
REPRESENTATIVE = {
    "normal": "EQP-001",
    "chamber_pressure_high": "EQP-008",
    "chamber_temp_drift": "EQP-004",
    "secs_link_unstable": "EQP-002",
}

FAILURES: list = []


def check(name: str, cond: bool, detail: str = "") -> None:
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def call_all(eqp: str) -> dict:
    return {
        "secs_link_status": secs_link_status(eqp),
        "chamber_pressure": chamber_pressure(eqp),
        "chiller_temp": chiller_temp(eqp),
        "wafer_yield_trend": wafer_yield_trend(eqp),
        "equipment_alarm_list": equipment_alarm_list(eqp),
    }


def main() -> int:
    print("=" * 62)
    print("半导体 SECS/GEM 仿真探针 — 确定性 & 阈值验证")
    print("=" * 62)

    # ---- 1. 剧本映射正确 ----
    print("\n-- 1. 故障剧本映射 (equipment_id 哈希确定性) --")
    for cls, eqp in REPRESENTATIVE.items():
        check(f"_fault_class({eqp}) == {cls}", _fault_class(eqp) == cls,
              f"got {_fault_class(eqp)}")

    # ---- 2. 确定性: 同一设备两次调用结果完全一致 ----
    print("\n-- 2. 确定性 (同 equipment_id 两次调用, JSON 完全相等) --")
    for cls, eqp in REPRESENTATIVE.items():
        r1, r2 = call_all(eqp), call_all(eqp)
        for tool in r1:
            j1, j2 = json.dumps(r1[tool], sort_keys=True), json.dumps(r2[tool], sort_keys=True)
            check(f"{tool}({eqp}) [{cls}] 确定性", j1 == j2)

    # ---- 3. 阈值标记正确 ----
    print("\n-- 3. 阈值/告警标记 --")

    # 3.1 正常设备: 全部探针无告警
    eqp = REPRESENTATIVE["normal"]
    r = call_all(eqp)
    check(f"normal {eqp}: secs_link_status 无告警", r["secs_link_status"]["alarm"] is False)
    check(f"normal {eqp}: chamber_pressure 无告警", r["chamber_pressure"]["alarm"] is False)
    check(f"normal {eqp}: chiller_temp 状态 NORMAL",
          r["chiller_temp"]["status"] == "NORMAL" and r["chiller_temp"]["alarm"] is False)
    check(f"normal {eqp}: 良率无漂移", r["wafer_yield_trend"]["drift_detected"] is False)
    check(f"normal {eqp}: 告警列表无严重告警", r["equipment_alarm_list"]["alarm"] is False)

    # 3.2 腔压异常: 压力 >5 Torr 且 CRITICAL
    eqp = REPRESENTATIVE["chamber_pressure_high"]
    p = chamber_pressure(eqp)
    check(f"pressure_high {eqp}: 压力 >5 Torr", p["pressure_torr"] > 5.0,
          f"got {p['pressure_torr']}")
    check(f"pressure_high {eqp}: 状态 CRITICAL", p["status"] == "CRITICAL")
    check(f"pressure_high {eqp}: alarm=True 且给出根因", p["alarm"] is True and len(p["likely_causes"]) >= 3)

    # 3.3 温控漂移: 供水温度偏差 >1.5°C 且 CRITICAL, 良率检出漂移
    eqp = REPRESENTATIVE["chamber_temp_drift"]
    t = chiller_temp(eqp)
    check(f"temp_drift {eqp}: 偏差 >1.5 °C", t["deviation_from_setpoint_c"] > 1.5,
          f"got {t['deviation_from_setpoint_c']}")
    check(f"temp_drift {eqp}: 状态 CRITICAL", t["status"] == "CRITICAL")
    y = wafer_yield_trend(eqp)
    check(f"temp_drift {eqp}: 良率漂移检出 (slope < -0.05 %/h)",
          y["drift_detected"] is True and y["slope_pct_per_hour"] < -0.05,
          f"slope={y['slope_pct_per_hour']}")
    check(f"temp_drift {eqp}: 良率呈下滑 (drop>0)", y["drop_pct"] > 0, f"drop={y['drop_pct']}")

    # 3.4 链路异常: NOT_SELECTED 且 T3/T5 计数高
    eqp = REPRESENTATIVE["secs_link_unstable"]
    s = secs_link_status(eqp)
    check(f"link_unstable {eqp}: hsms_state == NOT_SELECTED", s["hsms_state"] == "NOT_SELECTED")
    check(f"link_unstable {eqp}: selected=False 且 alarm=True",
          s["selected"] is False and s["alarm"] is True)
    check(f"link_unstable {eqp}: T3 超时 >=4 次/24h", s["t3_timeout_count_24h"] >= 4)
    check(f"link_unstable {eqp}: 事件含 T3/T5 timeout",
          {"T3_TIMEOUT", "T5_TIMEOUT"} <= {e["type"] for e in s["events_recent"]})

    # ---- 4. 告警列表与剧本交叉一致 ----
    print("\n-- 4. 告警列表 (GEM ALID) 与剧本交叉一致 --")
    expected_sets = {
        "chamber_pressure_high": {1201001, 1201102, 1506003},
        "chamber_temp_drift": {1202005, 1202107, 1404008},
        "secs_link_unstable": {1303001, 1303002, 1303003},
    }
    for cls, expect in expected_sets.items():
        eqp = REPRESENTATIVE[cls]
        a = equipment_alarm_list(eqp)
        actual = {x["alid"] for x in a["alarms"] if x["state"] == "SET"}
        check(f"{eqp} [{cls}] SET ALID 集合一致", actual == expect,
              f"got {sorted(actual)}, expect {sorted(expect)}")
        check(f"{eqp} [{cls}] alarm=True", a["alarm"] is True)

    # ---- 5. 参数裁剪 & 边界 ----
    print("\n-- 5. 参数边界 --")
    y1 = wafer_yield_trend("EQP-001", hours=999)   # 裁剪到 168
    check("hours=999 裁剪到 168", y1["window_hours"] == 168)
    y2 = wafer_yield_trend("EQP-001", hours=0)     # 提升到 1
    check("hours=0 提升到 1", y2["window_hours"] == 1)
    y3 = wafer_yield_trend("EQP-001", hours="abc") # 非法值回退 24
    check("hours='abc' 回退 24", y3["window_hours"] == 24)
    err = chamber_pressure("   ")
    check("空 equipment_id 返回 error", "error" in err)
    check("equipment_id 大小写归一 (eqp-001 == EQP-001)",
          json.dumps(chamber_pressure("eqp-001"), sort_keys=True)
          == json.dumps(chamber_pressure("EQP-001"), sort_keys=True))

    # ---- 结果 ----
    print("\n" + "=" * 62)
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} 项未通过: {FAILURES}")
        return 1
    print("PASS: 全部断言通过 (确定性 / 阈值标记 / 剧本交叉一致 / 参数边界)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
