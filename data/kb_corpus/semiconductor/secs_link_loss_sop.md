# SOP: SECS/GEM 通信链路中断与握手重连 (HSMS Link Loss)

## 适用范围
- 机型: 所有通过 SECS/GEM 与 MES/host 通信的半导体设备 (HSMS-SS 单会话为主, SEMI E37/E30/E5 标准)
- 告警来源: GEM ALID 1303001 (HSMS T3 reply timeout)、1303002 (HSMS T5 connect separation timeout)、1303003 (HSMS link NOT_SELECTED, host communication lost)
- 触发条件: host 侧显示设备 offline / 收不到 collect event / S5F1 告警缺失 / HSMS 状态机离开 SELECTED
- 责任角色: 设备工程师 (EE) 或 CIM/自动化工程师主导, IT 网络组配合

## 症状特征
- host GEM gateway 上设备状态变为 offline, 数据采集中断 (无 S6F11 事件上报)
- 设备端 HSMS 状态机: SELECTED → NOT CONNECTED (TCP 断开) 或卡在 CONNECT/NOT_SELECTED (TCP 通但 Select 失败)
- 事件日志出现 T3/T5/T6/T7 超时与 LINK_DOWN, 重连呈指数退避
- 批次可以继续跑 (设备本地缓存), 但结束后 host 收不到 Wafer Complete 事件, MES 过账滞后
- 判读要点: TCP 断开型 (LINK_DOWN) 查网络; TCP 通但 NOT_SELECTED 查 Select 握手与 GEM 配置

## HSMS 超时参数语义 (排障前必读)
| 参数 | 含义 | 默认值 | 超时典型指向 |
|---|---|---|---|
| T3 | 回复超时: primary 消息发出后等待 reply 的最长时间 | 45 s | 接收方应用 (GEM driver) 响应慢/挂起, 或消息未达 |
| T5 | 连接分离超时: TCP 建连后需等待的最小分离时间, 避免旧连接复用 | 10 s | 频繁 T5 → 对端反复建连断连, IP/端口冲突或重连风暴 |
| T6 | 控制事务超时: Select/Deselect/Linktest 等控制事务的最长等待 | 5 s | 对端 HSMS 控制进程无响应 (半死状态) |
| T7 | NOT SELECTED 期限: TCP 建立后多久内未完成 Select 则断开 | 10 s | 卡 T7 → Select.rsp 不回: device_id 不匹配或 GEM 未就绪 |
| T8 | 网络字节传输超时 (单消息收完) | 5 s | 网络拥塞/分片异常, 查网络层 |

## 排查流程
1. **定位断点层次** (先网络后应用):
   - 从 host 侧 ping 设备 & `telnet <设备IP> 5000` (HSMS 标准端口): TCP 不通 → 查交换机/网线/设备网卡, 转 IT 网络组
   - TCP 通但仍是 NOT_CONNECTED → 查防火墙/ACL 是否放行长连接与空闲超时 (idle timeout 把连接踢掉)
2. **看 GEM 状态机与握手日志**:
   - 设备端事件: Select.req 收到了吗? Select.rsp 回了吗 (状态码 0=接受, 1=拒绝, 2=忙)?
   - Select 被拒 (状态 1) → 核对 device_id 与 session_id 双端一致、设备 IP 白名单是否含 host IP、HSMS active/passive 模式配置 (双 active 会互相拒绝)
   - T7 超时 (发 Select 无响应) → 设备 GEM driver 未就绪或进程挂起, 重启设备端 GEM 通信进程
3. **区分超时类型**:
   - 仅 T3 偶发 (≤2 次/24h): 观察即可, 常为 host 负载高
   - T3 频繁 (≥5 次): host GEM driver 处理积压 — 查 host 侧消息队列深度、线程池; 也可能是 T8 网络传输慢
   - T5 重试堆积: 对端反复断连 — 查双方重连策略是否都在指数退避, 是否存在第二个 host 抢连接 (IP 冲突)
   - Linktest (T6) 失败: 连接半死 — 检查中间防火墙 session 老化策略, 建议缩短 Linktest 周期小于防火墙 idle timeout
4. **host 重连策略核对**: 确认 host 侧为指数退避 (如 5s→10s→20s→60s 上限), 避免重连风暴压垮设备端; 双 active/passive 模式: 推荐 host=active、设备=passive
5. **恢复后数据补齐**: 链路恢复 SELECTED 后, 核对设备本地缓存事件按序补发 (S6F11 重传/离线日志上传), 驱动 MES 过账补齐, 确认无批次数据丢失

## 常见根因与概率
| 根因 | 概率 | 典型证据 |
|---|---|---|
| 网络/防火墙层故障 (交换机口、网线、idle timeout 踢连接) | ~30% | LINK_DOWN 频繁, telnet 不通或时通时断 |
| host GEM driver/gateway 异常 (进程挂起、消息积压) | ~25% | T3 频繁超时, host 侧队列深 |
| 设备端 GEM 通信进程异常 (driver 未就绪/崩溃) | ~20% | Select 无响应卡 T7, 重启进程即恢复 |
| GEM 配置不匹配 (device_id/session_id/IP 白名单/active-passive) | ~15% | Select.rsp 拒绝 (状态 1), 配置变更后首发 |
| 设备主机资源耗尽 (CPU/内存打满导致通信线程饿死) | ~10% | 伴随设备端系统高负载告警 |

## 处置措施
1. **紧急止损**:
   - 设备允许本地模式继续跑批次时, 切 GEM offline (通讯指示灯 OFF) 保生产, 事后补传
   - 重启 host 侧 GEM gateway 或设备端通信进程 (按影响面小的一侧先动; 需 EE/CIM 确认窗口)
   - 明确 IP 冲突/第二 host 抢连接时, 断开非法端并固化 ARP/端口分配表
2. **配置修正**: 统一双端 device_id/session_id/模式 (host=active, 设备=passive); 白名单补 host IP; 防火墙放行并调大 idle timeout (或缩短 Linktest 周期至其 2/3 以内)
3. **host 侧优化**: GEM driver 消息处理线程池扩容, 积压时丢弃过期 Linktest; 重连统一指数退避 + 抖动 (jitter), 防止重连风暴
4. **恢复验证**: HSMS 回到 SELECTED 且稳定 ≥30 min; Linktest 周期性成功; 补发一段 S1F13/S1F14 (通信建立确认) 与 S1F1/S1F2 (Are You There) 验证双向; 确认 ALID 1303001/1303002/1303003 均 CLEAR
5. **记录**: 事件时间线 (LINK_DOWN→重连成功)、超时类型统计、根因与处置归档, 更新链路健康度评分

## 预防措施
- 双端部署 HSMS 链路监控: SELECTED 状态、T3/T5/T6 计数、Linktest 成功率纳入实时看板, 偏离基线自动告警
- Linktest 周期设为防火墙 idle timeout 的 2/3 以内 (如防火墙 30 min, Linktest ≤20 min)
- host GEM gateway 高可用 (主备), 重连策略统一指数退避+jitter, 禁用秒级固定重试
- 变更管理: 动 device_id/IP/白名单/通信模式必须双端同步变更并走评审
- 定期 (季度) 演练链路中断-恢复, 验证离线事件缓存补发完整性
