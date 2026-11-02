# 钓鱼邮件审核页面 — 执行计划

日期: 2026-10-30
Spec: `docs/superpowers/specs/2026-10-30-email-triage-frontend-design.md`

## 任务清单

### 阶段 1: 骨架接入
- [x] 1.1 `frontend/correlation.js`: `switchSecopsMode` 扩三态 — "email" 模式
      互斥显示 `#secops-email-wrap`, 隐藏单条/关联区块; 芯片 on/aria-pressed 同步
- [x] 1.2 `frontend/index.html`: 模式切换加第三芯片 `#secops-mode-email` +
      hint 文案更新; 邮件研判区块骨架 (输入区 / 简化流水 / 判定结果面板 /
      报告区容器); 底部引入 `email.js`

### 阶段 2: 核心逻辑 (`frontend/email.js` 新文件)
- [x] 2.1 文本入口: `startEmailTriage()` — 读 textarea + 备注, POST
      `/secops/email/triage`, `consumeSSE` 流式消费, AbortController 支持停止
- [x] 2.2 SSE 事件渲染 `handleEmailEvent()`: start/parsing/analyzing/report/
      complete/error 六事件 + 截图入口 transcribing/transcript 两事件;
      parsing 事件到达即渲染确定性信号 (先到先显)
- [x] 2.3 判定结果面板: 四态大徽章 (配色映射) + 置信度 + phishing_type
      中文标签 + intent_summary + 信号计数; degraded 状态提示
- [x] 2.4 报告区渲染: indicators 信号卡 (类别徽章 + description + evidence
      引用块, 全程 escapeHtml) / deterministic_signals 标 [代码验证] 徽章 /
      spoofing_analysis + verdict_reason / headers 键值表 + URL/附件清单
      (纯文本展示) / verification_playbook 步骤卡 (外链 noopener 新窗口 +
      command 一键复制)
- [x] 2.5 截图入口: FileReader 读 base64 → POST `/secops/email/triage/image`,
      mime 取文件实际类型; 校验 png/jpeg/gif/webp

### 阶段 3: 样式
- [x] 3.1 `frontend/styles.css`: 四态徽章 (`.email-verdict.v-phishing` 等) /
      信号卡 / 证据引用块 / 剧本步骤卡 / 流水阶段复用 `.secops-stage` 体系;
      亮暗两主题过 `var(--*)` 自动适配

### 阶段 4: 验证与收尾
- [x] 4.1 端到端验证: 启动服务, 用测试用例邮件 (凭据钓鱼样本) 走通
      文本入口 + 确定性信号先显 + 四态徽章 + 剧本渲染; `node --check`
      三个 js 文件语法
      (追加发现并修复后端 SSE 序列化 bug — 见任务日志; 前端链路用
      Node+DOM stub 对真实抓包验证 14 项断言全过)
- [x] 4.2 记录任务日志 `docs/task-log/2026-10-30.md`
