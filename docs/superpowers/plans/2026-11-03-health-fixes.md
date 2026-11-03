# 项目健康审查修复计划

日期: 2026-11-03
来源: docs/project-health-review-2026-11-03.md (第五节建议顺序)

## 批 1: 事件循环阻塞双修 (稳定性)
- [x] 1a. threat_intel.py enrich_iocs: 同步 web_search 串行 → asyncio.to_thread + gather 并发
- [x] 1b. llm.py _glm_rate_limit: 检测运行中事件循环时跳过同步 sleep (退化为 warn);
       _glm_last_call_ts 加锁修竞态; 注释说明同步上下文无法不阻塞等待的原因

## 批 2: 死代码与卫生清理 (零风险)
- [x] 2a. 删 agents/skill_router.py (178行) + agents/fork_runner.py (138行) — 删前 grep 双向复验零引用
- [x] 2b. ruff --select F401 --fix 清 8 处未用导入
- [x] 2c. data/ 残留清理: alert_history.jsonl.bak-e2e + secops_correlation 6 会话 +
       secops_sessions 的 e2e 会话 (保留 dlg-eval-*) + logs/ e2e 日志
- [x] 2d. .gitignore 补 data/*.db-* (消 git status 常驻噪音)

## 批 3: 经验库治理
- [x] 3a. milvus.py 加经验删除接口 (按 id / 按前缀匹配)
- [x] 3b. secops.py 加 DELETE /secops/experience 端点 (挂进历史管理 UI 语义, 默认需确认)
- [x] 3c. 删除评测残留的「RFC 保留段」经验; 报告/日志记录

## 批 4: 邮件研判沉淀 (SDD — 到时出 spec 停审批)

## 验证 (每批后): pytest 全量 + ruff + 批 1 加并发冒烟
