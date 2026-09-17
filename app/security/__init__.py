"""SecOps 安全告警研判域模块.

与 app/agents (AIOps 运维诊断域) 平级的第二个业务域:
  统一事件入口 → 域分类器 → SecOps 子图 (Triage→Scout→Enrich→Analyst→Critic→Reporter)

借鉴 (均重写为项目风格, 非直接移植):
  - SentinelOps (MIT): Supervisor→Scout→Analyst→Reporter 管线 + 置信度自主回环
  - OpenTriage (Apache 2.0): Markdown Playbook + Solver-Critic + 证据引用纪律
  - AiSOC: 证据链可回放 (Investigation Ledger 思想, 由 SSE trace 承担)

安全铁律: 研判产出永远是「建议 + 需人工审批」, 不接 remediation/action_executor
自动执行路径 (与 AIOps 域的自愈路径刻意隔离).
"""
