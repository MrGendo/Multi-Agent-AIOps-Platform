"""半导体设备 SECS/GEM 仿真探针 MCP Server.

为 AIOps 平台新增半导体设备工业场景支持 (蓝图「重构5」):
  - secs_link_status:     HSMS 链路状态仿真 (SELECTED / NOT_SELECTED / CONNECT)
  - chamber_pressure:     反应腔压力仿真 (正常 0.5~3 Torr)
  - chiller_temp:         冷却水机温度仿真 (设定 20±0.5 °C)
  - wafer_yield_trend:    晶圆良率趋势仿真 (时间序列, 可检出漂移)
  - equipment_alarm_list: SECS/GEM 标准告警仿真 (ALID / set / clear)

特点:
  - 全部只读、纯计算仿真, 无外部依赖 (不连真实设备, 不写任何状态)
  - 确定性: 所有伪数据按 equipment_id 哈希种子生成,
    同一 equipment_id 每次调用结果完全一致, 便于测试断言
  - 事件/趋势时间戳使用相对时间 (minutes_ago / hours_ago), 不取系统时钟,
    保证输出完全可复现

自检: .venv/bin/python mcp_servers/semicon_server.py --self-test
"""

from __future__ import annotations

import hashlib
import json
import random
from typing import Any, Dict, List

from fastmcp import FastMCP

mcp = FastMCP(name="SemiconductorProbeServer")

# ---------------------------------------------------------------------------
# 确定性伪数据基础设施
# ---------------------------------------------------------------------------

# 故障注入表: 按 equipment_id 哈希取模 10, 决定该设备的"固定剧本":
#   mode 0-6 -> 正常 (仅轻微噪声)
#   mode 7   -> 反应腔压力异常升高 (throttle valve / MFC 类故障)
#   mode 8   -> 冷却水温度漂移 + 良率同步下滑
#   mode 9   -> HSMS 链路不稳定 (T3/T5 超时, NOT_SELECTED)
_FAULT_CLASSES = {
    7: "chamber_pressure_high",
    8: "chamber_temp_drift",
    9: "secs_link_unstable",
}
FAULT_NORMAL = "normal"


def _fault_class(equipment_id: str) -> str:
    """按 equipment_id 哈希得到该设备的故障剧本 (确定性, 跨进程稳定)."""
    digest = hashlib.sha256(f"semicon|mode|{equipment_id}".encode("utf-8")).hexdigest()
    return _FAULT_CLASSES.get(int(digest[:8], 16) % 10, FAULT_NORMAL)


def _rng(equipment_id: str, domain: str) -> random.Random:
    """按 (domain, equipment_id) 派生独立确定性随机流.

    random.Random 接受字符串种子时内部走 sha512 摘要, 跨进程/跨平台确定,
    不受 PYTHONHASHSEED 影响.
    """
    digest = hashlib.sha256(f"semicon|{domain}|{equipment_id}".encode("utf-8")).hexdigest()
    return random.Random(digest)


def _norm_id(equipment_id: str) -> str:
    return (equipment_id or "").strip().upper()


# ---------------------------------------------------------------------------
# 工具 1: HSMS 链路状态
# ---------------------------------------------------------------------------


@mcp.tool(
    name="secs_link_status",
    description=(
        "查询设备的 SECS/GEM HSMS 通信链路状态仿真 (SEMI E37 标准). "
        "适用场景: 设备 'offline / 掉线 / 不上报数据 / host 收不到 collect event / "
        "SECS 通信超时 / T3 timeout' 等告警的排查入口. "
        "返回 hsms_state (SELECTED=链路正常选中 / NOT_SELECTED=TCP 通但 Select 未成功, "
        "常见 T5/T7 超时 / CONNECT=TCP 已建立正在选择 / NOT_CONNECTED=TCP 断开), "
        "近 24h T3(回复超时)/T5(连接分离超时) 计数, 以及带相对时间 (minutes_ago) 的事件日志. "
        "判读标准: SELECTED 且 t3_timeout_count_24h<=2 为健康; SELECTED 但 T3 频繁 (>=5) "
        "通常指向 host 侧 GEM driver 响应慢或网络抖动; NOT_SELECTED+T5 重试堆积 "
        "通常指向 TCP 可达但 Select 被拒 (equipment GEM 配置/IP 白名单/device_id 不匹配). "
        "数据为确定性仿真: 同一 equipment_id 每次返回完全一致, 便于测试断言; 只读."
    ),
)
def secs_link_status(equipment_id: str) -> Dict[str, Any]:
    eqp = _norm_id(equipment_id)
    if not eqp:
        return {"error": "equipment_id 不能为空"}

    fault = _fault_class(eqp)
    rng = _rng(eqp, "secs_link")

    events: List[Dict[str, Any]] = []
    if fault == "secs_link_unstable":
        # TCP 建立但 Select 反复失败: T5 分离超时 + T3 残留 + 间歇 T6
        state = "NOT_SELECTED"
        t3 = rng.randint(4, 9)
        t5 = rng.randint(2, 5)
        t6 = rng.randint(1, 3)
        events.append({"minutes_ago": 12, "type": "SELECT_FAIL",
                       "detail": "Select.req 发出后未在 T7=10s 内收到 Select.rsp, 设备侧拒绝 (device_id 不匹配或 GEM driver 未就绪)"})
        events.append({"minutes_ago": 18, "type": "T5_TIMEOUT",
                       "detail": "connect separation timeout: TCP 建连后 T5=10s 内未完成 Select 握手, 断开重连"})
        events.append({"minutes_ago": 47, "type": "T3_TIMEOUT",
                       "detail": "primary 消息 S2F41 (Remote Command) 在 T3=45s 内未收到 reply, 已重试"})
        events.append({"minutes_ago": 63, "type": "T6_TIMEOUT",
                       "detail": "control transaction (Linktest.req) 超过 T6=5s 未响应"})
        events.append({"minutes_ago": 121, "type": "LINK_DOWN",
                       "detail": "HSMS TCP 连接被设备侧断开, 进入重连队列 (指数退避)"})
        assessment = "异常: HSMS 链路无法进入 SELECTED, host 与设备间工艺数据/事件上报中断"
        alarm = True
    else:
        sub = rng.randint(0, 9)
        t5 = 0
        t6 = 0
        if sub <= 6:
            state = "SELECTED"
            t3 = rng.randint(0, 2)  # 偶发 T3 (健康链路也允许少量出现)
            if t3:
                events.append({"minutes_ago": rng.randint(60, 600), "type": "T3_TIMEOUT",
                               "detail": f"偶发 T3 reply timeout: primary 消息 S6F12 应答慢, 单次 {t3} 条, 未复发"})
            events.append({"minutes_ago": rng.randint(720, 2160), "type": "SELECT",
                           "detail": "Select.req/Select.rsp 握手成功, 链路进入 SELECTED, S1F13/S1F14 通信建立确认通过"})
            assessment = "正常: 链路 SELECTED 稳定, 偶发 T3 在允许范围内"
            alarm = False
        elif sub <= 8:
            state = "CONNECT"
            t3 = 0
            events.append({"minutes_ago": 3, "type": "LINK_UP",
                           "detail": "TCP 三次握手完成 (5000 端口), 等待 Select 握手, 链路建立中"})
            events.append({"minutes_ago": 6, "type": "DESELECT",
                           "detail": "host 主动 Deselect, 链路重建 (常见于 host 侧 GEM gateway 轮询重启)"})
            assessment = "正常: 链路处于 CONNECT (选择中), 数分钟内应转为 SELECTED; 长期停留才需关注"
            alarm = False
        else:
            state = "SELECTED"
            t3 = rng.randint(3, 4)
            events.append({"minutes_ago": rng.randint(20, 90), "type": "T3_TIMEOUT",
                           "detail": "T3 reply timeout 出现 3-4 次/24h: host GEM driver 响应偏慢或网络抖动, 建议观察"})
            events.append({"minutes_ago": rng.randint(720, 1440), "type": "SELECT",
                           "detail": "Select 握手成功, 链路 SELECTED"})
            assessment = "关注: 链路 SELECTED 但 T3 超时偏多 (3-4 次/24h), 未达告警阈值但呈恶化趋势"
            alarm = False

    return {
        "equipment_id": eqp,
        "probe": "secs_link_status (HSMS/SECS-I 仿真探针, SEMI E5/E30/E37)",
        "hsms_state": state,
        "selected": state == "SELECTED",
        "t3_timeout_count_24h": t3,
        "t5_retry_count_24h": t5,
        "t6_timeout_count_24h": t6,
        "t3_timeout_definition": "T3=回复超时(默认45s): primary 消息发出后未收到 reply",
        "t5_timeout_definition": "T5=连接分离超时(默认10s): TCP 建连后需等待的分离时间",
        "events_recent": sorted(events, key=lambda e: e["minutes_ago"]),
        "alarm": alarm,
        "assessment": assessment,
    }


# ---------------------------------------------------------------------------
# 工具 2: 反应腔压力
# ---------------------------------------------------------------------------


@mcp.tool(
    name="chamber_pressure",
    description=(
        "查询设备反应腔 (process chamber) 压力仿真, 单位 Torr. "
        "适用场景: 'chamber pressure high / 压力异常 / 真空异常 / 刻蚀或沉积工艺报警 / "
        "pressure interlock 触发' 等告警. "
        "判读标准: 正常工艺压力区间 0.5~3.0 Torr; 3.0~5.0 Torr 为 WARNING "
        "(可能为放气不充分或传感器漂移); **>5 Torr 为 CRITICAL, 通常指向 throttle valve "
        "(节流阀) 卡滞/故障或 MFC (质量流量控制器) 漂移/零漂, 亦需排查干泵前级性能衰减**. "
        "返回当前压力、10 分钟压力趋势、状态分级与 likely_causes 根因提示. "
        "数据为确定性仿真: 同一 equipment_id 每次返回完全一致; 只读."
    ),
)
def chamber_pressure(equipment_id: str) -> Dict[str, Any]:
    eqp = _norm_id(equipment_id)
    if not eqp:
        return {"error": "equipment_id 不能为空"}

    fault = _fault_class(eqp)
    rng = _rng(eqp, "chamber_pressure")

    if fault == "chamber_pressure_high":
        # 压力从工艺区间向上漂移, 当前值进入危急区
        current = round(rng.uniform(5.8, 9.2), 2)
        trend = [round(2.0 + (current - 2.0) * (i / 9.0) + rng.uniform(-0.2, 0.2), 2) for i in range(10)]
        trend[-1] = current
    else:
        current = round(rng.uniform(0.8, 2.6), 2)
        trend = [round(current + rng.uniform(-0.15, 0.15), 2) for _ in range(10)]

    if current >= 5.0:
        status = "CRITICAL"
        causes = [
            "throttle valve (蝶阀/节流阀) 卡滞或位置反馈漂移 — 最常见",
            "MFC (质量流量控制器) 零漂或量程漂移, 工艺气体实际流量偏大",
            "干泵/分子泵前级性能衰减 (pump oil 返流、叶片磨损), 抽速下降",
            "腔体密封圈 (O-ring) 老化导致微漏 (放气后 Base Pressure 不达标)",
        ]
    elif current >= 3.0:
        status = "WARNING"
        causes = [
            "腔体放气不充分 / N2 purge 未完成即开工艺",
            "压力传感器 (Pirani/Capacitance Manometer) 零点漂移",
        ]
    else:
        status = "NORMAL"
        causes = []

    return {
        "equipment_id": eqp,
        "probe": "chamber_pressure (反应腔压力仿真探针)",
        "chamber": "ProcessChamber-1",
        "pressure_torr": current,
        "unit": "Torr",
        "normal_range_torr": [0.5, 3.0],
        "warning_threshold_torr": 3.0,
        "critical_threshold_torr": 5.0,
        "trend_last_10min_torr": trend,
        "status": status,
        "alarm": current >= 5.0,
        "likely_causes": causes,
        "assessment": (
            f"当前压力 {current} Torr, 状态 {status}. "
            + (">5 Torr 通常指向 throttle valve 故障或 MFC 漂移, 参考 SOP: chamber_pressure_high_sop."
               if status == "CRITICAL" else "在正常工艺区间内." if status == "NORMAL"
               else "超出正常区间但未到危急阈值, 建议复测并观察趋势.")
        ),
    }


# ---------------------------------------------------------------------------
# 工具 3: 冷却水机温度
# ---------------------------------------------------------------------------


@mcp.tool(
    name="chiller_temp",
    description=(
        "查询设备冷却水机 (chiller) 温度仿真, 单位 °C, 设定值 20.0. "
        "适用场景: 'chiller 温度告警 / 冷却水温度高 / 设备过热 / 良率下滑疑似温控问题'. "
        "判读标准: 供水温度 20±0.5 °C 为正常 (NORMAL); 偏差 0.5~1.5 °C 为 WARNING; "
        "**偏差 >1.5 °C 为 CRITICAL — 供水温度每升高 1 °C, 刻蚀速率与关键尺寸 (CD) "
        "会随之漂移, 持续高温通常伴随良率下滑, 排查链路: chiller 制冷机组 → 冷却水流量 "
        "(过滤器压差/气泡) → 板式换热器结垢 → 工艺 recipe 热负载**. "
        "同时返回供水/回水温度与流量, 回水-供水温差过大说明热负载高或流量不足. "
        "数据为确定性仿真: 同一 equipment_id 每次返回完全一致; 只读."
    ),
)
def chiller_temp(equipment_id: str) -> Dict[str, Any]:
    eqp = _norm_id(equipment_id)
    if not eqp:
        return {"error": "equipment_id 不能为空"}

    fault = _fault_class(eqp)
    rng = _rng(eqp, "chiller_temp")

    setpoint = 20.0
    if fault == "chamber_temp_drift":
        supply = round(rng.uniform(21.6, 23.8), 2)
        flow = round(rng.uniform(12.0, 22.0), 1)
    else:
        supply = round(rng.uniform(19.6, 20.4), 2)
        flow = round(rng.uniform(28.0, 42.0), 1)

    delta_return = round(rng.uniform(1.2, 2.8), 2)
    ret = round(supply + delta_return, 2)
    delta = round(abs(supply - setpoint), 2)

    if delta > 1.5:
        status = "CRITICAL"
    elif delta > 0.5:
        status = "WARNING"
    else:
        status = "NORMAL"

    if status == "NORMAL":
        causes = []
    else:
        causes = [
            "chiller 制冷机组异常 (压缩机效率下降 / 制冷剂泄漏 / 冷凝器脏堵)",
            "冷却水流量不足 (过滤器堵塞压差大 / 管路气泡 / 循环泵衰减)",
            "板式换热器 (heat exchanger) 结垢, 换热效率下降",
            "工艺 recipe 热负载升高 (RF power 提升 / 新腔体镀膜导致吸热特性变化)",
        ]

    return {
        "equipment_id": eqp,
        "probe": "chiller_temp (冷却水机温度仿真探针)",
        "setpoint_c": setpoint,
        "supply_temp_c": supply,
        "return_temp_c": ret,
        "supply_return_delta_c": delta_return,
        "coolant_flow_lpm": flow,
        "deviation_from_setpoint_c": delta,
        "normal_band_c": [19.5, 20.5],
        "status": status,
        "alarm": delta > 0.5,
        "likely_causes": causes,
        "yield_impact_hint": (
            "供水温度每 +1 °C, 刻蚀速率/CD 通常发生可观漂移; 若同时观察到良率趋势下滑, "
            "优先排查本链路 (参考 SOP: chiller_temp_drift_sop)."
        ) if status != "NORMAL" else "",
        "assessment": (
            f"供水温度 {supply} °C (设定 {setpoint} ±0.5), 偏差 {delta} °C, 状态 {status}; "
            f"冷却水流量 {flow} L/min."
        ),
    }


# ---------------------------------------------------------------------------
# 工具 4: 良率趋势
# ---------------------------------------------------------------------------


@mcp.tool(
    name="wafer_yield_trend",
    description=(
        "查询设备晶圆 (wafer) 良率趋势仿真时间序列, 用于检出工艺漂移. "
        "适用场景: '良率下滑 / yield drop / CD 漂移 / 工艺不稳定 / 批次不良率升高'. "
        "判读标准: 斜率 slope_pct_per_hour < -0.05 (%/h) 判定为漂移 (drift_detected=true); "
        "当前良率 < 90% 或首尾差 > 5 个百分点同样触发告警. "
        "**良率持续下滑 + chiller 供水温度同步偏高 → 高度怀疑温控链路 "
        "(chiller/流量/换热器); 良率下滑 + 腔压偏高 → 怀疑 throttle valve/MFC; "
        "良率正常但通信告警多 → 大概率仅 host 数据采集中断而非工艺问题**. "
        "hours 默认 24 (1~168, 采样点最多 48 个, 时间标签为相对的 hours_ago). "
        "数据为确定性仿真: 同一 equipment_id+hours 每次返回完全一致; 只读."
    ),
)
def wafer_yield_trend(equipment_id: str, hours: int = 24) -> Dict[str, Any]:
    eqp = _norm_id(equipment_id)
    if not eqp:
        return {"error": "equipment_id 不能为空"}
    try:
        hours = int(hours)
    except (TypeError, ValueError):
        hours = 24
    hours = max(1, min(hours, 168))

    fault = _fault_class(eqp)
    rng = _rng(eqp, "wafer_yield")

    n = min(hours, 48)
    baseline = rng.uniform(93.5, 97.5)
    if fault == "chamber_temp_drift":
        slope = rng.uniform(-0.28, -0.16)   # 温控漂移 → 明显下滑
    elif fault == "chamber_pressure_high":
        slope = rng.uniform(-0.12, -0.05)   # 腔压异常 → 轻度下滑
    else:
        slope = rng.uniform(-0.01, 0.01)    # 正常 → 平稳

    series = [round(baseline + slope * i + rng.uniform(-0.6, 0.6), 2) for i in range(n)]
    points = [
        {"hours_ago": round((n - 1 - i) * (hours / n), 1), "yield_pct": v}
        for i, v in enumerate(series)
    ]

    # 最小二乘斜率 (%/h, 采样间隔 hours/n 小时)
    step = hours / n
    slope_fit = _linreg_slope(series) / step if step else 0.0
    slope_fit = round(slope_fit, 4)
    first_half = series[: n // 2] or series
    second_half = series[n // 2:] or series
    avg_first = round(sum(first_half) / len(first_half), 2)
    avg_second = round(sum(second_half) / len(second_half), 2)
    drift = slope_fit < -0.05
    low_yield = series[-1] < 90.0
    big_drop = (series[0] - series[-1]) > 5.0

    hint = ""
    if fault == "chamber_temp_drift":
        hint = "良率单调下滑且斜率与温控漂移量级吻合, 建议联动 chiller_temp 探针交叉印证 (SOP: chiller_temp_drift_sop)."
    elif fault == "chamber_pressure_high":
        hint = "良率伴随腔压异常轻度下滑, 建议联动 chamber_pressure 探针交叉印证 (SOP: chamber_pressure_high_sop)."

    return {
        "equipment_id": eqp,
        "probe": "wafer_yield_trend (良率趋势仿真探针)",
        "window_hours": hours,
        "points": points,
        "baseline_yield_pct": series[0],
        "current_yield_pct": series[-1],
        "slope_pct_per_hour": slope_fit,
        "drift_threshold_pct_per_hour": -0.05,
        "drift_detected": drift,
        "first_half_avg_pct": avg_first,
        "second_half_avg_pct": avg_second,
        "drop_pct": round(series[0] - series[-1], 2),
        "alarm": drift or low_yield or big_drop,
        "correlation_hint": hint,
        "assessment": (
            f"窗口 {hours}h: 首段均值 {avg_first}% → 尾段均值 {avg_second}%, "
            f"拟合斜率 {slope_fit} %/h, {'检出漂移' if drift else '未见显著漂移'}."
        ),
    }


def _linreg_slope(ys: List[float]) -> float:
    """最小二乘斜率 (点/步), n<2 时返回 0."""
    n = len(ys)
    if n < 2:
        return 0.0
    mean_x = (n - 1) / 2.0
    mean_y = sum(ys) / n
    num = sum((i - mean_x) * (y - mean_y) for i, y in enumerate(ys))
    den = sum((i - mean_x) ** 2 for i in range(n))
    return num / den if den else 0.0


# ---------------------------------------------------------------------------
# 工具 5: SECS/GEM 告警列表
# ---------------------------------------------------------------------------

# GEM (SEMI E30) 告警模型: ALID = CA 分类字节 + 告警编号; SET/CLEAR 经 S5F1 上报,
# 告警使能由 S2F37 控制. 以下目录参考真实 GEM ALID 命名习惯.
_ALARM_CATALOG: List[Dict[str, Any]] = [
    {"alid": 1201001, "severity": "ERROR", "enabled": True,
     "text_en": "Chamber pressure above critical threshold",
     "text_zh": "反应腔压力超过危急阈值 (ProcessChamber-1)"},
    {"alid": 1201102, "severity": "ERROR", "enabled": True,
     "text_en": "Throttle valve position deviation",
     "text_zh": "节流阀 (throttle valve) 位置偏差超限"},
    {"alid": 1506003, "severity": "ERROR", "enabled": True,
     "text_en": "Dry pump foreline pressure high",
     "text_zh": "干泵前级压力偏高, 疑似抽速衰减"},
    {"alid": 1202005, "severity": "ERROR", "enabled": True,
     "text_en": "Chiller supply temperature out of range",
     "text_zh": "冷却水机供水温度超出 20±0.5 °C 范围"},
    {"alid": 1202107, "severity": "WARNING", "enabled": True,
     "text_en": "Coolant flow below low limit",
     "text_zh": "冷却水流量低于下限"},
    {"alid": 1404008, "severity": "WARNING", "enabled": True,
     "text_en": "Wafer yield trend drift detected",
     "text_zh": "晶圆良率趋势漂移检出 (斜率 < -0.05 %/h)"},
    {"alid": 1303001, "severity": "ERROR", "enabled": True,
     "text_en": "HSMS T3 reply timeout",
     "text_zh": "HSMS 链路 T3 回复超时"},
    {"alid": 1303002, "severity": "ERROR", "enabled": True,
     "text_en": "HSMS T5 connect separation timeout",
     "text_zh": "HSMS 连接分离超时 (T5), Select 握手未完成"},
    {"alid": 1303003, "severity": "FATAL", "enabled": True,
     "text_en": "HSMS link NOT_SELECTED, host communication lost",
     "text_zh": "HSMS 链路未选中, host 通信中断"},
    {"alid": 1405010, "severity": "WARNING", "enabled": True,
     "text_en": "Process recipe parameter out of window",
     "text_zh": "工艺配方参数超出窗口 (SPC 判异)"},
]

# 故障剧本 -> 应处于 SET 状态的 ALID 集合 (保证与其它探针交叉一致)
_CLASS_SET_ALIDS = {
    "chamber_pressure_high": {1201001, 1201102, 1506003},
    "chamber_temp_drift": {1202005, 1202107, 1404008},
    "secs_link_unstable": {1303001, 1303002, 1303003},
}


@mcp.tool(
    name="equipment_alarm_list",
    description=(
        "查询设备 SECS/GEM 标准告警列表仿真 (参考 SEMI E30 告警模型: "
        "ALID 编号 + 报警文本 + SET/CLEAR 状态, SET/CLEAR 经 S5F1 上报). "
        "适用场景: 任何半导体设备告警的**第一入口** — 先看本列表确定激活的 ALID, "
        "再决定调用哪个探针深挖 (压力类 ALID→chamber_pressure, 温控类→chiller_temp, "
        "通信类 1303xxx→secs_link_status, 良率类 1404xxx→wafer_yield_trend). "
        "判读标准: severity FATAL/ERROR 的 SET 告警需立即处置; WARNING 仅观察. "
        "alarm=true 表示存在激活的 FATAL/ERROR 告警. "
        "数据为确定性仿真: 同一 equipment_id 每次返回完全一致; 只读."
    ),
)
def equipment_alarm_list(equipment_id: str) -> Dict[str, Any]:
    eqp = _norm_id(equipment_id)
    if not eqp:
        return {"error": "equipment_id 不能为空"}

    fault = _fault_class(eqp)
    rng = _rng(eqp, "alarm_list")
    set_alids = set(_CLASS_SET_ALIDS.get(fault, set()))

    # 正常设备也可能有一条 SPC 类 WARNING 处于 SET (贴近真实)
    minor_set = (not set_alids) and rng.randint(0, 2) == 0
    if minor_set:
        set_alids = {1405010}

    alarms: List[Dict[str, Any]] = []
    for entry in _ALARM_CATALOG:
        alid = entry["alid"]
        is_set = alid in set_alids
        item = {
            "alid": alid,
            "severity": entry["severity"],
            "enabled": entry["enabled"],
            "state": "SET" if is_set else "CLEAR",
            "text_en": entry["text_en"],
            "text_zh": entry["text_zh"],
        }
        if is_set:
            item["set_minutes_ago"] = rng.randint(5, 240)
        alarms.append(item)

    active = [a for a in alarms if a["state"] == "SET"]
    active_serious = [a for a in active if a["severity"] in ("FATAL", "ERROR")]

    return {
        "equipment_id": eqp,
        "probe": "equipment_alarm_list (SECS/GEM 告警列表仿真探针)",
        "format_note": "GEM E30: ALID = CA 分类字节 + 告警编号; SET/CLEAR 经 S5F1 上报, 使能由 S2F37 控制",
        "total": len(alarms),
        "active_count": len(active),
        "alarms": alarms,
        "alarm": bool(active_serious),
        "active_serious_alids": [a["alid"] for a in active_serious],
        "assessment": (
            f"共 {len(active)} 条 SET 告警, 其中 FATAL/ERROR {len(active_serious)} 条; "
            + ("需按 SOP 立即处置." if active_serious else "无激活的严重告警.")
        ),
    }


# ---------------------------------------------------------------------------
# 自检 & 启动
# ---------------------------------------------------------------------------


def _self_test() -> int:
    """CI 自检: 不起 http 服务, 直接调用 5 个工具函数打印结果."""
    tools = [
        ("secs_link_status", secs_link_status),
        ("chamber_pressure", chamber_pressure),
        ("chiller_temp", chiller_temp),
        ("wafer_yield_trend", wafer_yield_trend),
        ("equipment_alarm_list", equipment_alarm_list),
    ]

    # 1) 扫描故障剧本分布 (确定性)
    classes: Dict[str, List[str]] = {}
    for i in range(1, 41):
        eqp = f"EQP-{i:03d}"
        classes.setdefault(_fault_class(eqp), []).append(eqp)
    print("== fault class distribution (EQP-001..EQP-040, deterministic) ==")
    for cls in sorted(classes):
        print(f"  {cls:<22} n={len(classes[cls]):>2}  e.g. {classes[cls][:4]}")

    # 2) 每个剧本选一个代表设备, 打印全部工具输出
    for cls in ("normal", "chamber_pressure_high", "chamber_temp_drift", "secs_link_unstable"):
        reps = classes.get(cls) or ["EQP-001"]
        eqp = reps[0]
        print(f"\n== representative equipment [{cls}]: {eqp} ==")
        for name, fn in tools:
            kwargs = {"hours": 24} if name == "wafer_yield_trend" else {}
            result = fn(eqp, **kwargs)
            print(f"-- {name}({eqp}{', hours=24' if kwargs else ''}) --")
            print(json.dumps(result, ensure_ascii=False, indent=2))

    print("\n[self-test] all 5 probes executed OK")
    return 0


if __name__ == "__main__":
    import sys

    if "--self-test" in sys.argv:
        raise SystemExit(_self_test())
    print("[mcp] semicon_server starting on http://0.0.0.0:8012/mcp ...")
    mcp.run(transport="streamable-http", host="0.0.0.0", port=8012)
