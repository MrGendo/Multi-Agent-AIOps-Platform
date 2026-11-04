# 告警/邮件研判结果推送 (飞书·企微·邮件) 设计规格

日期: 2026-11-04
状态: 待审批
前置: webhook 全自动研判链路 (webhook.py _run_triage_background) + 邮件研判管线

## 1. 目标

研判结论不再只躺在 history 与 UI — 高危结果实时推送人:
飞书群机器人 / 企业微信群机器人 / SMTP 邮件三渠道, 分级触发, 防轰炸。

## 2. 模块设计 — `app/core/notifier.py` (新)

### 2.1 渠道发送 (全 fail-soft, 推送失败绝不影响研判主流程)

| 渠道 | 机制 | 消息形态 |
|------|------|---------|
| 飞书 | 群机器人 webhook (settings 配置 URL) — 一个 HTTP POST | interactive 卡片: 标题色随级别 (红=malicious/phishing), 判定/置信/类型/关键 IOC/一句话理由 |
| 企业微信 | 群机器人 webhook 同理 | markdown 消息 (同内容降级排版) |
| 邮件 | smtplib + SMTP 配置 (SSL/STARTTLS) | 纯文本 (标题 + 详情块), 收件人列表可配 |

三渠道互相独立, 任何一路失败只记日志。httpx 走 to_thread (沿用批 1 纪律,
不在事件循环里同步 POST); SMTP 同样 to_thread。

### 2.2 触发判定 — `should_notify(kind, verdict, severity) -> bool`

- 告警研判: `verdict == malicious` 或 `severity >= NOTIFY_MIN_SEVERITY` (默认 HIGH)
- 邮件研判: `classification == phishing` 且非 degraded (NOTIFY_ON_PHISHING, 默认开)
- 总开关 `NOTIFY_ENABLED` (默认 false — 不配置渠道 URL 时天然静默, 行为与现状一致)

### 2.3 防轰炸 (webhook 全自动场景的告警风暴)

滑动窗口 (60s) 每渠道计数: 超过 NOTIFY_RATE_LIMIT (默认 8) 条后本窗口抑制,
窗口结束合并推一条「窗口内另有 N 条同类告警被抑制」。实现为进程内
`{channel: (window_start, count, suppressed)}` 三元组, 无锁竞态容忍 (计数偏差
可接受, 不值得上锁)。

### 2.4 触发点 (两处, 各一行调用)

1. `webhook.py _run_triage_background` 研判落 history 后: fire-and-forget
   `notify_security(...)` (进批 4 建立的 `_email_bg_tasks` 同款引用池模式)
2. `secops.py` 邮件 SSE complete 后 (与经验提炼同位): fire-and-forget `notify_email(...)`

手动 UI 研判 (/secops/triage 前端) **不推送** — 人就在看, 推是打扰;
只推"无人值守"路径 (webhook 自动研判 + 邮件管线)。

## 3. 配置 (settings + .env.example 登记)

```
NOTIFY_ENABLED=false            # 总开关 (默认关 — 现状行为不变)
NOTIFY_FEISHU_WEBHOOK=          # 空=该渠道不启用
NOTIFY_WECOM_WEBHOOK=
NOTIFY_SMTP_HOST= / _PORT=465 / _USER= / _PASS= / _FROM= / _TO=  # 逗号分隔多收件
NOTIFY_MIN_SEVERITY=HIGH        # 告警推送阈值
NOTIFY_ON_PHISHING=true         # 钓鱼判定推送
NOTIFY_RATE_LIMIT=8             # 每渠道每分钟
```

## 4. 文件改动

| 文件 | 改动 |
|------|------|
| `app/core/notifier.py` (新) | 渠道发送 + should_notify + 限流 (~150 行) |
| `app/api/v1/webhook.py` | 研判后 fire-and-forget 通知 (引用池) |
| `app/api/v1/secops.py` | 邮件 complete 后同位通知 |
| `app/config.py` + `.env.example` | 上述配置登记 |
| `tests/test_notifier.py` (新) | 渠道 mock (httpx/smtplib) + 阈值/开关/限流/防轰炸 |

## 5. 验收标准

1. NOTIFY_ENABLED=false (默认): 全链路行为与现状逐字节一致, 零外呼
2. 配置飞书 URL + 模拟 malicious 告警 → 收到卡片 POST (mock httpx 断言 URL/JSON 结构);
   benign 不推
3. 限流: 第 9 条起抑制, 窗口合并推送一条汇总
4. 任一渠道配置错/网络失败: 只记 warning, 研判与其余渠道不受影响
5. 真实飞书/企微机器人实测一轮 (用户提供测试群 webhook 或以 beeper 类占位验证)
