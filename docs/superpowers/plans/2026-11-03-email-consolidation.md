# 邮件研判沉淀 — 执行计划

日期: 2026-11-03
Spec: docs/superpowers/specs/2026-11-03-email-consolidation-design.md

## 任务清单

- [x] 1. `app/security/email_history.py` (新): append/query/sender_domain_stats,
      倒序尾读 (只读尾部块, 不全量加载 — 吸取 alert_history 慢性性能教训)
- [x] 2. `consolidation.py` + consolidate_email_verdict: phishing 且非 degraded 才
      提炼入库 (source=email_experience, 补 h1/h2/h3, split_markdown)
- [x] 3. `email_triage.py` 注入: 同域历史事实块 (已验证事实格式) + 经验召回参考块
      (明示仅供参考); 空数据时与现状逐字节一致
- [x] 4. `secops.py`: 注入调用 + complete 后 fire-and-forget consolidate +
      GET /email/history 端点
- [x] 5. tests: email_history 单测 + 注入断言 (mock) + SSE 序列不变回归
- [x] 6. 验证: pytest 全量 + 真实跑一封钓鱼邮件两轮 (第二轮应见历史注入) +
      任务日志
