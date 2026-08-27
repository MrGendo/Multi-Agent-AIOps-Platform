"""LLM 降级规则引擎 (Rule-Engine Fallback).

为什么需要:
  LLM 厂商 API 5xx/超时/配额耗尽时, 诊断流程不能整体瘫痪.
  本模块用纯规则 (关键词匹配 + 模板) 生成基础排障建议, 保障
  「降级可用」: 无 LLM 也能给出方向正确的 OnCall 建议与置信度.

定位:
  - 输出质量 << LLM, 但零依赖、毫秒级、永不失败
  - 由上层在 LLM 不可用时调用 (failover 路径), 同时用于 LLM 健康探测
  - 纯函数模块, 导入零副作用

用法:
    >>> from app.core.rule_engine import rule_engine_diagnose
    >>> md, confidence = rule_engine_diagnose("服务器磁盘空间不足 C盘满了")
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass(frozen=True)
class DiagnosisRule:
    """一条降级诊断规则."""
    rule_id: str
    keywords: Tuple[str, ...]          # 中英文关键词 (小写匹配)
    severity: str                      # critical / high / medium / low
    summary: str                       # 一句话结论
    actions: Tuple[str, ...]           # 排查/处置动作 (有序)
    first_probe: str = ""              # 建议首个排查动作 (供上层自动执行)


# ============================================================
# 规则库 (覆盖 IT 运维 + 半导体设备两大域)
# ============================================================
RULES: List[DiagnosisRule] = [
    DiagnosisRule(
        rule_id="disk_full",
        keywords=("磁盘", "disk", "c盘", "空间不足", "no space left", "diskfull", "存储满"),
        severity="high",
        summary="磁盘空间不足, 写入受阻, 可能引发服务崩溃与日志丢失",
        actions=(
            "1. `df -h` / Windows 查各分区水位, 定位满盘分区",
            "2. `du -sh /* 2>/dev/null | sort -h` 找大目录 (常见: 日志/临时文件/Docker 层)",
            "3. 清理过期日志与临时文件: journalctl --vacuum-size=500M, docker system prune",
            "4. 检查日志轮转配置 (logrotate) 是否失效",
            "5. 必要时扩容磁盘或迁移大文件到对象存储",
        ),
        first_probe="检查磁盘水位与大目录",
    ),
    DiagnosisRule(
        rule_id="cpu_high",
        keywords=("cpu", "负载高", "高负载", "load average", "处理器", "cpu使用率"),
        severity="medium",
        summary="CPU 高负载, 可能是业务高峰、死循环或异常进程",
        actions=(
            "1. `top -c` / `htop` 找 CPU 最高进程, 区分 us/sy/wa (用户/内核/IO等待)",
            "2. wa 高 → 磁盘 IO 瓶颈, 转 IO 排查; us 高 → 应用层问题",
            "3. `pidstat -p <pid> 1 5` 看线程级热点",
            "4. 对可疑进程 `py-spy dump` / `jstack` 抓栈定位死循环",
        ),
        first_probe="定位 CPU 热点进程",
    ),
    DiagnosisRule(
        rule_id="memory_leak",
        keywords=("内存", "memory", "oom", "泄漏", "leak", "out of memory", "内存溢出", "swap"),
        severity="high",
        summary="内存泄漏或 OOM 风险, 可能触发内核 OOM Killer 杀进程",
        actions=(
            "1. `free -h` 看可用内存与 swap 使用; `dmesg | grep -i oom` 查 OOM 记录",
            "2. 定位内存增长进程: `ps aux --sort=-%mem | head`",
            "3. 对嫌疑进程抓堆: Java `jmap -histo <pid>`, Python tracemalloc, Go pprof",
            "4. 短期缓解: 滚动重启泄漏进程 (带健康检查); 长期: 修复泄漏或加内存限制",
        ),
        first_probe="确认 OOM 事件与泄漏进程",
    ),
    DiagnosisRule(
        rule_id="service_down",
        keywords=("服务不可用", "进程挂", "服务挂", "service down", "crash", "崩溃", "502", "503", "退出", "exit code", "restart"),
        severity="critical",
        summary="服务不可用/进程崩溃, 属最高优先级, 先恢复再查因",
        actions=(
            "1. 确认进程状态: systemctl status / docker ps -a / kubectl get pods",
            "2. 看退出码与最近日志: journalctl -u <svc> -n 200 / docker logs --tail 200",
            "3. 先恢复业务: 重启服务 (若配置了自动重启确认其健康)",
            "4. 查崩溃模式: 立即崩 (配置/依赖问题) vs 运行一段时间崩 (资源/泄漏)",
        ),
        first_probe="确认进程状态与最近崩溃日志",
    ),
    DiagnosisRule(
        rule_id="db_conn_fail",
        keywords=("数据库", "database", "mysql", "postgres", "postgresql", "连接失败", "connection refused", "too many connections", "db"),
        severity="critical",
        summary="数据库连接失败, 通常是连接数耗尽、DB 宕机或网络不通",
        actions=(
            "1. 分层探测: 应用 → `telnet db 3306` 通不通 → DB 进程活不活",
            "2. 连接数: MySQL `show processlist` / PG `select count(*) from pg_stat_activity`",
            "3. 连接池泄漏是常见根因: 检查应用连接池配置 (max_size/回收时间)",
            "4. DB 活着但拒绝连接 → 检查 max_connections 与防火墙",
        ),
        first_probe="分层探测网络→DB进程→连接数",
    ),
    DiagnosisRule(
        rule_id="network_issue",
        keywords=("网络", "network", "超时", "timeout", "ping", "不通", "丢包", "packet loss", "dns", "延迟高"),
        severity="high",
        summary="网络不通/超时/丢包, 需分层定位 (链路→路由→DNS→应用层)",
        actions=(
            "1. `ping <target>` 看通断与 RTT; `mtr <target>` 看丢包在哪一跳",
            "2. DNS: `dig <domain>` / `nslookup`, 排查解析失败或错误解析",
            "3. 端口层: `telnet`/`nc -zv host port` 确认服务端口可达",
            "4. 抓包定位: `tcpdump -i any host <ip> -w /tmp/p.pcap` (必要时)",
        ),
        first_probe="ping + mtr 分层探测",
    ),
    DiagnosisRule(
        rule_id="redis_conn_fail",
        keywords=("redis", "缓存", "cache", "缓存失败"),
        severity="high",
        summary="Redis 连接失败/缓存异常, 关注内存淘汰与主从切换",
        actions=(
            "1. `redis-cli ping` 确认存活; `redis-cli info memory` 看内存与淘汰策略",
            "2. `redis-cli info stats | grep -E 'evicted|keyspace'` 看是否大量淘汰",
            "3. 慢查询: `redis-cli slowlog get 10`",
            "4. 若主从架构, 确认是否发生了 failover (info replication)",
        ),
        first_probe="redis ping + 内存水位",
    ),
    DiagnosisRule(
        rule_id="secs_link_loss",
        keywords=("secs", "gem", "hsms", "链路中断", "通信中断", "设备通信", "equipment offline", "设备离线"),
        severity="critical",
        summary="SECS/GEM 链路中断, 设备与 HOST 通信断开, 影响生产追踪与自动控制",
        actions=(
            "1. 确认 HSMS 状态: SELECTED / NOT SELECTED / CONNECT (设备侧 T3 timeout 日志)",
            "2. 网络层: 设备口 ping/telnet 5000 端口, 排除交换机/网线",
            "3. GEM 状态机: 若处于 NOT SELECTED, 检查 Host 端 Select 状态与 T5 重连间隔",
            "4. 查设备端 SECS 日志的 T3/T5/T6 超时记录, 区分网络超时 vs 应用无响应",
            "5. 恢复顺序: 先恢复链路 (重连), 再补传中断期间离线缓存的事件",
        ),
        first_probe="确认 HSMS 链路状态与 SECS 超时日志",
    ),
    DiagnosisRule(
        rule_id="chamber_pressure_high",
        keywords=("反应腔", "chamber", "压力", "pressure", "torr", "真空度", "真空"),
        severity="critical",
        summary="反应腔压力异常, 可能指向 throttle valve 故障、MFC 漂移或泵性能衰减",
        actions=(
            "1. 读当前腔压与设定值偏差; >5 Torr 通常指向 throttle valve 故障或 MFC 漂移",
            "2. 检查 pump 抽速: 比较 dry pump 当前电流/温度与基线",
            "3. 检查 MFC 流量读数与 recipe 设定是否一致 (气路泄漏会拉高腔压)",
            "4. 查 throttle valve 开度反馈是否卡死 (开度不变+压力爬升 = 阀卡)",
            "5. 处置: 停工艺、N2 吹扫、按厂商 SOP 检修; 严禁带压拆腔",
        ),
        first_probe="读腔压趋势与 pump/MFC 基线对比",
    ),
    DiagnosisRule(
        rule_id="chiller_temp_drift",
        keywords=("冷却", "chiller", "温度漂移", "水温", "良率", "yield", "温控", "过热"),
        severity="high",
        summary="冷却水温度漂移, 会直接传导到工艺温度造成良率下降",
        actions=(
            "1. 对比 chiller 出水温度设定 (通常 20°C) 与实际, >±0.5°C 即漂移",
            "2. 检查冷却水流量与管路 (流量不足→换热差); 查水垢/过滤器堵塞",
            "3. 检查热交换器与环境温度 (夏季进水温度升高是常见诱因)",
            "4. 关联分析: 良率漂移时间点 vs 温度漂移时间点是否吻合",
            "5. 处置: 切换备用 chiller (若有), 检修温控 PID 与压缩机",
        ),
        first_probe="chiller 出水温度 vs 设定值",
    ),
]


# ============================================================
# 匹配与诊断
# ============================================================
def _match_rule(rule: DiagnosisRule, query_lower: str) -> int:
    """返回规则命中关键词数 (0 = 未命中)."""
    hits = 0
    for kw in rule.keywords:
        if kw in query_lower:
            hits += 1
    return hits


GENERIC_ONCALL_TEMPLATE = """## 降级模式: 通用 OnCall 排查清单

未匹配到专项规则, 以下通用排查顺序供参考:

1. **确认影响面**: 哪些服务/用户受影响, 从何时开始
2. **最近变更**: 是否有发布/配置变更/扩缩容 (时间相关性)
3. **基础资源**: CPU / 内存 / 磁盘 / 网络 四项水位
4. **依赖服务**: 下游 DB/缓存/MQ 状态与连接数
5. **日志证据**: 应用 ERROR 日志与系统日志 (dmesg/journal) 时间线

> 注: 当前 LLM 不可用, 本建议由规则引擎降级生成, 置信度较低.
"""


def rule_engine_diagnose(query: str) -> Tuple[str, float]:
    """规则引擎降级诊断.

    Args:
        query: 告警/故障描述文本

    Returns:
        (markdown 建议文本, 置信度 0-1)
        置信度: 命中词数最多的规则 → 0.3 + 0.15 * (命中词数-1), 上限 0.85;
        无命中 → 通用清单, 0.1
    """
    if not query or not query.strip():
        return GENERIC_ONCALL_TEMPLATE, 0.1

    q = query.lower()
    scored: List[Tuple[int, DiagnosisRule]] = []
    for rule in RULES:
        hits = _match_rule(rule, q)
        if hits > 0:
            scored.append((hits, rule))

    if not scored:
        return GENERIC_ONCALL_TEMPLATE, 0.1

    # 命中词数降序; 并列时按规则定义顺序 (稳定排序保确定性)
    scored.sort(key=lambda x: -x[0])
    top_hits = scored[0][0]
    # 所有命中规则全部输出 (跨域复合故障常见, 如网络+DB 同时异常);
    # 置信度由最强命中的规则决定
    matched = [r for _, r in scored]

    parts: List[str] = []
    if len(matched) > 1:
        parts.append(f"> ⚠️ 多个规则同时命中 ({len(matched)} 条), 可能是跨域复合故障\n")

    for rule in matched:
        parts.append(f"## [{rule.severity.upper()}] {rule.summary}")
        parts.append("")
        parts.append(f"规则: `{rule.rule_id}` | 置信来源: 命中 {top_hits} 个特征词")
        parts.append("")
        parts.append("**排查与处置建议**:")
        parts.append("")
        parts.extend(rule.actions)
        parts.append("")

    confidence = min(0.85, 0.3 + 0.15 * (top_hits - 1))
    parts.append("---")
    parts.append("> 注: 当前 LLM 不可用, 本建议由规则引擎降级生成.")
    return "\n".join(parts), confidence


def first_probe_for(query: str) -> str:
    """返回最佳匹配规则的 first_probe (无匹配返回空串)."""
    q = (query or "").lower()
    best: Tuple[int, DiagnosisRule] = (0, RULES[0])  # type: ignore[assignment]
    for rule in RULES:
        hits = _match_rule(rule, q)
        if hits > best[0]:
            best = (hits, rule)
    return best[1].first_probe if best[0] > 0 else ""


# 预编译敏感词正则 (供日志脱敏复用): 无
_ = re  # silence unused import warning if re unused in future edits
