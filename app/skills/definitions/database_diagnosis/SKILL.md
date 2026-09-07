---
name: database_diagnosis
display_name: 数据库诊断 (MySQL/PostgreSQL/Redis/MongoDB)
description: 排查数据库类故障：MySQL/PostgreSQL 慢查询/连接池耗尽/复制延迟/锁等待，Redis 内存满/OOM/持久化失败/主从断连，MongoDB 副本集异常。先 search_knowledge_base 查专用 SOP（docs/sop/redis_oncall_sop.md、mysql_oncall_sop.md 已入库），再用 check_port/http_check/execute_python_script 实连实例采集真实指标
triggers:
  - 数据库
  - mysql
  - postgresql
  - postgres
  - redis
  - mongodb
  - 慢查询
  - 连接池
  - 复制延迟
  - 主从
  - 锁等待
  - 慢 SQL
  - 内存满
  - used_memory
  - maxmemory
  - 持久化
  - aof
  - rdb
  - 副本集
  - 连接数
allowed_tools:
  - search_knowledge_base
  - get_current_time
  - check_port
  - http_check
  - dns_lookup
  - execute_python_script
  - list_available_secrets
  - delegate_to_evidence_collector
  - delegate_to_kb_researcher
risk_level: medium
---

# 数据库诊断 Playbook (MySQL/PostgreSQL/Redis/MongoDB)

## 适用场景
- 数据库连接失败 / 连接超时 / 突然变慢
- 数据库内存告警 (如 Redis used_memory 逼近 maxmemory)
- 主从 / 复制异常 (复制延迟 / 主从断连)
- 慢查询 / 慢 SQL / 锁等待堆积
- 连接池耗尽 ("too many connections" 类报错)

## 不适用场景
- 本机没有数据库实例 — **不编造数据**, 改查知识库 SOP 给通用处置建议, 并在结论里如实报告「未发现实例」
- 非数据库问题 (CPU/磁盘/网络/容器) → 转对应 skill

## Phase 1: 信息收集
1. 从输入抽取**数据库类型 / host / port**
2. 未说 host → 默认尝试 127.0.0.1; 未说 port → 按类型用常规端口:
   - MySQL: 3306
   - PostgreSQL: 5432
   - Redis: 6379
   - MongoDB: 27017
3. 用 `check_port(host, port)` 探活:
   - 通 → 接 Phase 2
   - 不通 → 实例未监听 / 防火墙拦截 / 进程挂了, 结合知识库 SOP 给建议

## Phase 2: 分支诊断 (先查知识库再动手)
### MySQL
- 关注: 连接数 / 慢查询 / 锁等待
- 先 `search_knowledge_base` 查 mysql SOP (mysql_oncall_sop.md 已入库)

### Redis
- 关注: used_memory / maxmemory / evicted_keys / OOM / 持久化失败
- 先 `search_knowledge_base` 查 redis SOP 第一章 (redis_oncall_sop.md 已入库)

### PostgreSQL
- 关注: 复制延迟 / 连接池耗尽

### MongoDB
- 关注: 副本集状态异常 (rs.status / 成员 HEALTH)

## Phase 3: 实连采集
- 用 `execute_python_script` 发 socket / RESP PING 或 redis-cli 兼容探测, 采集真实指标
- 代码保持简短、**只读优先** (INFO / PING / SELECT 类查询), 不执行任何写操作
- 需要凭证时先 `list_available_secrets` 查有哪些 `SECRET_*` 可注入, **禁止硬编码或凭空猜密码**

## 输出格式
- **结论**: 一句话根因判断
- **证据**: 具体指标 + 来源 (哪个工具 / 哪条 SOP)
- **处置建议**: 可执行的动作清单
- **是否需要人工介入**: 是/否 + 理由

## 注意事项
- **全自动无人值守诊断 — 严禁反问用户**; 信息不足时基于现有信息推理并**标注假设**继续
- 工具查不到就如实报告「工具不可用 / 无数据」并继续
- 任何写操作 (重启 / 清数据 / 改配置) 仅作建议, 不自主执行
