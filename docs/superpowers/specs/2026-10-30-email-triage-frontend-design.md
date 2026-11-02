# 钓鱼邮件审核页面 (Email Triage Frontend) 设计规格

日期: 2026-10-30
状态: 待审批
范围: 仅前端 (frontend/),后端接口已存在且不改

## 1. 背景与目标

后端已实现邮件分诊管线 (`app/security/email_triage.py` + `app/api/v1/secops.py`):

- `POST /api/v1/secops/email/triage` — 粘贴邮件原文 (.eml 源码或摘录), SSE 流式研判
- `POST /api/v1/secops/email/triage/image` — 邮件截图, 视觉模型转写后走同一管线

前端零覆盖: `frontend/` 中 grep 不到任何 email 相关调用, 现有 SecOps 输入框
(`secops-query`) 走的是通用告警五阶段管线 (`/secops/triage`), 不会触发邮件
专用分析 (邮件头解析 / 发件人欺骗检测 / URL 欺骗模式 / 危险附件识别)。

**目标**: 补一个邮件审核工作台 — 原始邮件粘贴 / 截图上传两种入口, 流式展示
确定性信号 (先到先显) 与 LLM 研判结论 (四态判定 + 判断依据 + 验证剧本)。

## 2. 入口形态: SecOps Tab 第三态模式芯片

现有"单条研判 ↔ 关联研判"双态芯片 (`correlation.js switchSecopsMode`) 扩为三态:

```
[单条研判] [关联研判] [邮件研判]   ← 新增第三芯片
```

理由:
- 后端接口归属 secops 域 (`/secops/email/triage`), 与告警研判同属安全运营
- 双态切换机制已存在, 扩三态是最小改动; 不新增顶层 tab, 保持 4-tab 信息架构
- 邮件工作流 (输入形态 / SSE 事件 / 结果渲染) 与告警研判完全不同, 必须
  独立区块互斥显示, 不能复用告警输入框

## 3. UI 布局 (邮件研判模式独占区块, 与单条/关联互斥)

```
┌─────────────────────────────────────────────────────┐
│ ① 输入区                                             │
│  [邮件原文 textarea rows=10]  ← 粘 .eml 源码或摘录    │
│  [分析师备注 input]  [📷 截图] [开始研判] [停止]       │
├──────────────────────┬──────────────────────────────┤
│ ② 过程区 (左)         │ ③ 判定结果面板 (右)           │
│ 简化阶段流水:          │ 四态大徽章 + 置信度           │
│ 解析→语义研判→报告     │ phishing_type 细分            │
│ (截图入口多一阶段:     │ intent_summary (想要什么)     │
│  转写)                │ 恶意信号计数 (代码 N · 语义 M) │
│ findings 事件流        │                              │
├──────────────────────┴──────────────────────────────┤
│ ④ 报告区 (研判完成后展示)                             │
│ 4.1 恶意信号明细: indicators 逐条 (类别徽章 + 说明 +   │
│     原文证据引用块), 确定性信号标 [代码验证] 徽章       │
│ 4.2 发件人身份分析 (spoofing_analysis) + 判定理由      │
│ 4.3 解析产物: headers 键值表 / URL 列表 / 附件列表     │
│ 4.4 安全验证剧本: 链接验证 + 附件验证步骤               │
│     (情报站外链新窗口开 / 命令一键复制)                │
└─────────────────────────────────────────────────────┘
```

四态配色 (复用现有 CSS 变量): phishing → `var(--red)`, spam → `var(--amber)`,
suspicious → 橙, benign → `var(--green)`。

## 4. SSE 事件契约 (以后端代码为准)

文本入口 (`/email/triage`):
| 事件 | 载荷 | 前端行为 |
|------|------|---------|
| start | stage/message | 状态"解析中", 流水亮"解析" |
| parsing | headers/urls/attachments/signals | **立即渲染确定性信号** (后端设计亮点: 毫秒级先给信号, 前端必须先显) |
| analyzing | message | 状态"语义研判中", 流水亮"研判" |
| report | result (完整 EmailVerdict + playbook) | 渲染报告区 |
| complete | session_id | 状态"完成 ✓" |
| error | message | 状态"失败 ✗" + 错误条 |

截图入口 (`/email/triage/image`) 在 start 后额外有:
| 事件 | 载荷 | 前端行为 |
|------|------|---------|
| transcribing | message | 流水亮"转写"阶段 |
| transcript | transcript | findings 展示转写文本 (折叠块) |
之后接同一 parsing→…→complete 序列。

`result` 关键字段: `classification` (phishing/spam/suspicious/benign 四态),
`confidence` (0-1), `phishing_type` (credential_phishing/malware_delivery/
bec_fraud/extortion_scam/lottery_scam/none), `intent_summary`,
`indicators[]` (category/description/evidence), `spoofing_analysis`,
`verdict_reason`, `parsed` (headers/urls/attachments/received_count),
`deterministic_signals[]`, `verification_playbook` (link_verification /
attachment_steps, 每步含 step/how/actions[{label,url}] 或 command),
`status` (ok/degraded — degraded 时提示"LLM 不可用, 仅确定性信号")。

## 5. 安全考量 (前端必须做对的部分)

1. **XSS 防线**: 邮件原文、headers、URL、附件名、evidence 全部是攻击者可控
   输入 — 一律 `escapeHtml()` 后再拼 HTML, 与现有 secops 渲染同纪律。
   URL 展示为纯文本 (mono 字体), 不渲染成可点击 `<a>` (防误点钓鱼链接,
   与后端 OPSEC "绝不自动访问" 原则一致)。
2. **playbook 外链**: urlscan/VT/whois 等情报站链接 `target="_blank"
   rel="noopener noreferrer"`; 这不是攻击者链接, 是分析师主动查询。
3. **复制按钮**: `navigator.clipboard` 包 try/catch, 失败降级为选中文本提示。

## 6. 文件改动清单

| 文件 | 改动 |
|------|------|
| `frontend/index.html` | 第三芯片 + hint 更新 + 邮件研判区块 HTML (输入/流水/结果/报告四区) + `<script src="/email.js">` |
| `frontend/correlation.js` | `switchSecopsMode` 双态 → 三态 (互斥显隐三个区块) |
| `frontend/email.js` (新) | 邮件研判全部逻辑: SSE 消费/事件渲染/四态徽章/信号卡/剧本渲染/截图上传。独立文件与 correlation.js 同模式, 避免继续膨胀 app.js (已 2000+ 行) |
| `frontend/styles.css` | 少量新样式: 四态徽章色 / 信号卡 / 证据引用块 / 剧本步骤卡 (全部复用现有 CSS 变量) |

## 7. 明确不做

- 不改任何后端代码 (接口已就绪且有测试 `tests/test_email_triage.py`)
- 不做邮件研判历史会话列表 (后端无查询接口)
- 不自动展开短链 / 不访问任何邮件内链接 (OPSEC)
