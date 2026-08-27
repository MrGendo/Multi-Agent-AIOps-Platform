# SOP: 反应腔压力异常升高诊断与自愈 (Chamber Pressure High)

## 适用范围
- 机型: 刻蚀 (Etch)、化学气相沉积 (CVD/PVD)、扩散等带真空反应腔的半导体工艺设备
- 告警来源: GEM ALID 1201001 (Chamber pressure above critical threshold)、1201102 (Throttle valve position deviation)、1506003 (Dry pump foreline pressure high)
- 触发条件: 工艺腔压力持续 >5 Torr (CRITICAL), 或 3~5 Torr (WARNING) 且伴随 pressure interlock
- 责任角色: 设备工程师 (EE) 主导, 工艺工程师 (PE) 配合判定工艺影响

## 症状特征
- 腔压读数偏离工艺设定窗口 (典型工艺区间 0.5~3 Torr), 呈缓升或台阶式跳变
- Pressure interlock 触发, 工艺中断或 recipe 拒绝启动
- S5F1 告警风暴: 1201001 SET 后常连带 1201102/1506003 同时 SET
- 伴随现象: 良率轻度下滑 (slope -0.05~-0.15 %/h)、base pressure 抽不下去、放气 (vent) 后回抽时间变长
- 判读要点: 压力**台阶式跳变**多指向阀卡滞或传感器故障; **缓慢爬升**多指向泵性能衰减或微漏

## 排查流程
1. **确认读数真实性** (5 min): 对比腔规 (Pirani vs Capacitance Manometer) 双通道读数; 单通道异常而另一通道正常 → 传感器零漂, 走校准流程, 不要急着拆阀
2. **看压力趋势形态**: 调取近 10 min 压力曲线 — 突变形 → 第 3 步; 缓升形 → 第 4 步
3. **突变排查**:
   - 检查 throttle valve (蝶阀) 位置反馈与设定偏差 (开度命令 vs 实际位置 >3% 即异常)
   - 手动模式下做 valve 全开/全归零动作测试, 观察是否卡滞 (电流偏大或行程超时)
   - 检查 MFC (质量流量控制器) 实际流量 vs 设定流量, 零漂 >1% F.S. 需校零
4. **缓升排查**:
   - 查干泵 (dry pump) 前级压力: >1 Torr 说明抽速衰减 (泵油返流/叶片磨损/消音器堵)
   - 查腔体密封: 放气至大气压后做 rate-of-rise 测试, 压升率超标 → O-ring 老化或微漏
   - 查工艺气体管路: 皂泡/氦检漏仪查接头
5. **联动判定**: 若同时有 chiller 温度告警, 先按 `chiller_temp_drift_sop` 排除温控干扰 (温度漂移也会间接影响真空泵抽速)

## 常见根因与概率
| 根因 | 概率 | 典型证据 |
|---|---|---|
| throttle valve 卡滞/位置反馈漂移 | ~35% | 阀位命令与反馈偏差 >3%, 突变形态 |
| MFC 零漂或量程漂移 | ~25% | 实际流量持续偏大, 工艺速率同步偏移 |
| 干泵/前级泵性能衰减 | ~20% | 前级压力高, 回抽时间变长, 泵体温度高 |
| 腔体密封圈老化微漏 | ~12% | rate-of-rise 超标, base pressure 不达标 |
| 压力传感器漂移 (误报) | ~8% | 双通道读数不一致, 趋势平稳 |

## 处置措施
1. **紧急止损 (自愈动作)**:
   - 腔压 >8 Torr: 触发软件 interlock 停止工艺, 关闭工艺气体 MFC, 保持 N2 purge
   - 对可复位告警下发 S2F41 远程命令执行 purge/abort cycle (需 EE 确认后执行)
   - throttle valve 位置漂移: 执行 valve re-home (归零校准) 例程, 成功率约 60%
2. **阀类故障**: 归零校准无效则安排停机换阀 (备件: throttle valve assembly), 换后做 leak check + rate-of-rise 验证
3. **MFC 故障**: 在线执行 MFC zero calibration; 校零后仍漂移 >1% F.S. 则换 MFC
4. **泵性能衰减**: 干泵做 override regeneration/换油; 前级压力仍高则评估换泵或大修 (按 PM 计划)
5. **密封微漏**: 定位后更换 O-ring, 按扭矩规范上紧, 复测压升率 <标准值
6. **恢复验证**: 处置后连续跑 3 片 monitor wafer, 确认腔压回 0.5~3 Torr 且 ALID 1201001 CLEAR (S5F1 上报), 良率趋势回稳
7. **记录**: 在 MES/设备历史中记录 ALID 时间线、根因与处置, 更新该机台健康度评分

## 安全注意事项
- 腔压异常时**严禁直接开腔**: 先确认工艺气体已关断并完成 N2 purge, 防止有毒/腐蚀性气体 (如 Cl2, BCl3, CF4 类) 泄漏
- 干泵性能衰减排查时注意泵体高温表面与出口废气 (接 scrubber/排气系统处理)
- throttle valve 手动测试必须在设备 offline + 无晶圆在腔状态下进行, 防止误动作损伤晶圆
- 涉及远程命令 (S2F41) 的自愈动作必须有 EE 在场确认, 禁止无人值守自动执行

## 相关 SOP 与工具
- 关联 SOP: `chiller_temp_drift_sop` (温控漂移也会间接影响真空系统), `secs_link_loss_sop` (若压力告警同时伴随 S5F1 上报中断)
- 诊断探针: `chamber_pressure(equipment_id)` / `equipment_alarm_list(equipment_id)` / `wafer_yield_trend(equipment_id)`
- 判读阈值以探针返回字段为准: normal_range 0.5~3 Torr, WARNING 3~5 Torr, CRITICAL >5 Torr

## 预防措施
- 纳入 PM (预防性维护): throttle valve 每 6 个月归零校准一次, O-ring 按开腔次数寿命更换
- 干泵按厂家小时数做保养, 监控前级压力趋势作为泵健康早期指标
- SPC 监控腔压 baseline 与回抽时间 (pump-down time), 趋劣提前介入
- MFC 定期 (季度) 校零, 工艺气体切换后必做零点检查
- 知识沉淀: 每次根因确认后回填本 SOP 的根因概率表与处置有效性数据
