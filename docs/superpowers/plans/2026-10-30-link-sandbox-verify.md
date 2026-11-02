# 链接沙箱自动验证 (urlscan L1) — 执行计划

日期: 2026-10-30
Spec: `docs/superpowers/specs/2026-10-30-link-sandbox-verify-design.md`

## 任务清单

### 阶段 1: 后端
- [x] 1.1 `app/config.py:84-91`: settings 加 `urlscan_api_key` (默认空=关闭) /
      `urlscan_visibility` (默认 public)
- [x] 1.2 `app/security/link_verifier.py` (新, 133 行): `verify_urls()` — 域名去重
      取前 3, asyncio.gather 并发; 单条 submit → 轮询 (60s 预算) → 判定 dict;
      httpx 仅打 urlscan.io; 全路径 fail-soft 不抛
- [x] 1.3 `app/api/v1/secops.py:596-643`: report 后插 verifying → link_report
      事件 (无 key/无 URL 跳过); parsing 事件带 `auto_verify` 字段

### 阶段 2: 前端
- [x] 2.1 `frontend/index.html:357-361`: 流水第五阶段"链接验证" (report 之后)
- [x] 2.2 `frontend/email.js:130` parsing 读 auto_verify 决定第五阶段
      active/skip; `:152-161` verifying/link_report 事件; `:269-305`
      renderLinkVerdicts 验证卡 (徽章四态 + 详情 + 截图外链 noopener)
- [x] 2.3 `frontend/styles.css:1145-1173`: lv-* 验证卡与徽章样式

### 阶段 3: 测试与验证
- [x] 3.1 `tests/test_link_verifier.py` (新, 8 用例): 正常恶意/干净判定 / 轮询
      超时 / 429 超额 / 无 key 短路 / 域名去重+limit / SSE 两态序列 — 全过
- [x] 3.2 端到端: 无 key 起服务, 事件序列与现状一致 (start→parsing→analyzing
      →report→complete), parsing.auto_verify=False; 真实 urlscan key 验证未做
      (用户未提供 key), 以 mock 覆盖为准
- [x] 3.3 任务日志已追加 `docs/task-log/2026-10-30.md`
