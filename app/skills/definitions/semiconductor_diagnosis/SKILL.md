---
name: semiconductor_diagnosis
display_name: 半导体设备排障 (SECS/GEM)
description: 排查半导体设备工业场景故障：SECS/GEM 通信中断、HSMS 超时、反应腔压力异常、冷却水机温度漂移、晶圆良率下滑。通过仿真探针采集设备链路状态/腔压/温控/良率趋势/GEM 告警列表后按 SOP 分支诊断
triggers:
  - 半导体
  - 晶圆
  - wafer
  - secs
  - gem
  - hsms
  - 设备离线
  - 设备掉线
  - chamber
  - 腔压
  - 反应腔
  - 真空异常
  - 压力异常
  - throttle valve
  - mfc
  - chiller
  - 冷却水
  - 温控漂移
  - 良率
  - yield
  - alid
  - t3 timeout
  - s5f1
allowed_tools:
  - search_knowledge_base
  - get_current_time
  - equipment_alarm_list
  - secs_link_status
  - chamber_pressure
  - chiller_temp
  - wafer_yield_trend
  - get_local_system_overview
  - get_local_cpu_memory
  - get_local_disk_usage
  - list_top_processes
  - web_search
risk_level: low
---

# 半导体设备排障 Playbook (SECS/GEM)

## 适用场景
- 设备 SECS/GEM 通信类告警: HSMS 掉线 / `NOT_SELECTED` / T3/T5/T6 timeout / host 收不到 collect event / S5F1 告警风暴
- 工艺腔体类告警: chamber pressure high / 真空异常 / pressure interlock 触发 / base pressure 不达标
- 温控类告警: chiller supply temp out of range / 冷却水温度高 / 设备过热降频
- 质量类告警: wafer yield drop / CD 漂移 / SPC 判异 / 批次不良率升高
- 用户提到"晶圆/wafer/刻蚀机/PVD/CVD 设备/SECS 掉线/良率掉了"等

**不适用**: 纯 IT 基础设施问题 (主机 CPU/内存 → `host_resource_diagnosis`; 网络 → `network_diagnosis`; 容器 → `container_diagnosis`)。

## 数据来源约束 (重要)
- 本 skill 的 5 个探针 (`equipment_alarm_list` / `secs_link_status` / `chamber_pressure` / `chiller_temp` / `wafer_yield_trend`) 返回的是**确定性仿真数据** (按 equipment_id 哈希生成, 同设备每次结果一致), 不是真实机台数据
- 汇报结论时必须注明"基于仿真探针数据", 禁止编造探针未返回的现场细节
- `search_knowledge_base` 可检索半导体 SOP 语料 (`data/kb_corpus/semiconductor/`) 作为排查思路参考

## Phase 1: 摸底 (必做, 一次调用定方向)
1. 从用户输入抽取**设备号 (equipment_id)**, 没说清楚就直接问 (不要猜设备号)
2. 调 `equipment_alarm_list(equipment_id)` 拿到当前 SET 的 GEM ALID 列表
3. 按 ALID 分层定方向:
   - `1303xxx` (HSMS/T3/T5/NOT_SELECTED) → 走 Phase 2-A 通信链路分支
   - `1201xxx`/`1506xxx` (腔压/throttle valve/干泵) → 走 Phase 2-B 腔压分支
   - `1202xxx` (chiller 温度/流量) + `1404xxx` (良率漂移) → 走 Phase 2-C 温控-良率分支
   - 仅 `1405xxx` WARNING (recipe 参数窗口) → 走 Phase 2-D 工艺漂移分支
   - 全 CLEAR → 设备当前无激活告警, 如用户仍报异常, 逐项跑 2-A~2-C 复核

## Phase 2-A: SECS/GEM 通信链路分支
1. 调 `secs_link_status(equipment_id)` 看 `hsms_state`:
   - `SELECTED` + T3≤2 次/24h → 链路健康, 问题可能在 host 侧采集
   - `SELECTED` 但 T3 3~4 次 → 观察; ≥5 次 → host GEM driver 响应慢或网络抖动
   - `CONNECT` 长期停留 → Select 握手卡住, 查 T7
   - `NOT_SELECTED` + T5 重试堆积 → TCP 通但 Select 被拒: 查 device_id 匹配 / 设备 IP 白名单 / GEM driver 状态
2. 读 `events_recent` 里的 T3/T5/T6/LINK_DOWN 事件类型与时间分布
3. 参考 SOP: `secs_link_loss_sop` (可用 `search_knowledge_base` 检索)

## Phase 2-B: 反应腔压力分支
1. 调 `chamber_pressure(equipment_id)`, 按返回 `status` 分级:
   - `NORMAL` (0.5~3 Torr) → 腔压无异常
   - `WARNING` (3~5 Torr) → 放气不充分或传感器漂移, 建议复测
   - `CRITICAL` (>5 Torr) → **通常指向 throttle valve 卡滞或 MFC 漂移, 亦需排查干泵前级性能衰减**
2. 看 `trend_last_10min_torr` 判断是突变 (interlock/阀卡) 还是缓升 (泵性能衰减/微漏)
3. 参考 SOP: `chamber_pressure_high_sop`

## Phase 2-C: 温控-良率联动分支
1. 调 `chiller_temp(equipment_id)`: 偏差 ≤0.5 °C 正常; 0.5~1.5 °C WARNING; **>1.5 °C CRITICAL**
2. 调 `wafer_yield_trend(equipment_id, hours=24)`: 看 `drift_detected` 与 `slope_pct_per_hour`
3. 交叉判读 (本场景核心思路):
   - 温度 CRITICAL + 良率 slope < -0.05 %/h → 高度怀疑温控链路, 排查顺序: chiller 制冷机组 → 冷却水流量 (过滤器压差) → 板式换热器结垢 → recipe 热负载
   - 温度正常 + 良率下滑 → 转 Phase 2-B 复核腔压, 或怀疑 recipe/气体/射频源
4. 参考 SOP: `chiller_temp_drift_sop`

## Phase 2-D: 工艺漂移分支
1. 调 `wafer_yield_trend(equipment_id)` 看趋势形态:
   - 单调下滑 → 缓慢漂移 (温控/腔压/部件老化)
   - 台阶式下跌 → 突发事件 (换批气体 / 部件更换 / recipe 变更)
   - 锯齿波动 → 工艺窗口偏窄或计量 (metrology) 噪声
2. 结合 2-B/2-C 探针数据交叉定位物理根因

## Phase 3: 输出报告
**现状快照** (ALID 列表 + 各探针关键数值: hsms_state / pressure_torr / supply_temp_c / yield slope) + **问题判断** (哪个子系统异常, 分级) + **最可能根因** (引用探针 likely_causes 与 SOP 概率排序) + **处置建议** (引用 SOP 的排查/自愈步骤) + **预防措施**。

报告必须写明:
- **数据来源**: "基于半导体仿真探针 (确定性仿真数据)"
- **具体数值**: 腔压 Torr / 温度 °C / 良率 % / T3 计数不能省
- **诚实表态**: 探针数据不足以定位时明确说明, 建议现场工程师按 SOP 复核

## 注意事项
- 全部探针**只读**, 不下发任何控制命令 (不发 S2F41 remote command, 不改 recipe, 不动阀)
- 涉及设备停机 / 换阀 / 换泵 / 修改 recipe 的处置, 必须建议设备工程师 (EE) 人工确认, **不要自主执行**
- HSMS 超时参数语义不要混: T3=回复超时 / T5=连接分离超时 / T6=控制事务超时 / T7=NOT_SELECTED 后等待 Select 超时
- 判读阈值以探针返回的 `normal_range` / `threshold` 字段为准, 不要凭记忆改阈值
