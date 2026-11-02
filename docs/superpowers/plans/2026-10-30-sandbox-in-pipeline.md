# 沙箱验证进研判路径 + 落地页语义判定 — 执行计划

日期: 2026-10-30
Spec: `docs/superpowers/specs/2026-10-30-sandbox-in-pipeline-design.md`

## 任务清单

### 阶段 1: link_verifier 升级 (语义验证)
- [x] 1.1 DOM 获取: result 轮询完成后拉 `urlscan.io/dom/{uuid}/`
      (含截图 b64 拉取); 实测确认免费档可访问性, 不行则降级跳过语义判定
- [x] 1.2 密码表单静态检测 `_detect_credential_form(dom, page_url)`:
      密码框存在性 + form action 域比对 (同域/异域/子域), 纯正则零依赖
- [x] 1.3 视觉 LLM 判定 `_judge_landing_page(screenshot_b64, mime, url, dom_hint)`:
      router 模型 + 结构化输出 (claimed_identity/credential_form/submits_to/
      impersonation/confidence); 失败 fail-soft 仅留确定性表单检测
- [x] 1.4 verify_urls 返回结构扩展 (每条加 dom 检测 + 语义判定 + 截图)

### 阶段 2: 研判注入与 SSE 重排
- [x] 2.1 `email_triage.analyze_email` 加 sandbox_evidence 参数: 注入
      _USER_TMPL + 系统提示纪律 + evidence 包含性校验 haystack 扩展
- [x] 2.2 `secops.py` SSE 重排: parsing 后立即并行提交沙箱 → verifying 事件
      → asyncio.wait(45s) → analyzing (带 sandbox_evidence) → report
      (result 含 sandbox_indicators) → complete; 超时任务取消 + link_report
      (cancelled)

### 阶段 3: 前端适配
- [x] 3.1 index.html 流水阶段换位 (verify 在 analyze 前); email.js 事件
      适配 (verifying 提前到达时机、analyzing 时 verify 收尾)
- [x] 3.2 sandbox_indicators 信号卡渲染 (徽章"沙箱验证"+ 声称身份/表单/
      提交目标/仿冒判定/置信度); 验证卡区数据源切换; 超时卡标注
- [x] 3.3 styles.css 补充 (如需)

### 阶段 4: 测试与验证
- [x] 4.1 单测: 密码表单四象限 / _judge_landing_page mock / SSE 两态序列
      (正常含 indicators + 超时 cancelled) / analyze_email 注入断言
- [x] 4.2 端到端: 无 key 行为不变; 有 key 用 example.com 真跑一轮看
      sandbox_indicators; 语义判定对"合法域仿冒页"以模拟 DOM 单测覆盖
- [x] 4.3 任务日志追加 `docs/task-log/2026-10-30.md`
