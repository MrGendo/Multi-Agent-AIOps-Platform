# 沙箱验证进研判路径 + 落地页语义判定 设计规格

日期: 2026-10-30
状态: 待审批
前置: 2026-10-30-link-sandbox-verify (urlscan L1 已上线, 结论后补模式)

## 1. 背景与动机

真实测试暴露两个结构性问题 (校内子域钓鱼案例 newcas.gzhu.edu.cn):

1. **评分盲区**: urlscan score 依赖黑名单/多引擎/已知 kit 特征 — "合法域下的
   恶意内容" (内部人用学校子域) 三条全空 → 0 分假干净。基础设施信号
   (域名年龄/证书) 对此类攻击天然失效, 页面语义 (仿冒登录页+密码表单)
   才是本质特征。
2. **后补不进判定**: 现状 report 先出 (LLM 只见邮件正文), verifying/link_report
   后补 — 邮件正文信号弱时 LLM 只能给 suspicious, 最有力的落地页证据
   在判定之后才到, 互不影响。与 SecOps 单条研判 "Scout 取证 → Analyst
   研判" 的先取证后研判哲学相悖。

## 2. 方案总览

```
旧: parsing → analyzing → report → verifying → link_report → complete
                        (LLM 无沙箱证据)     (结论后补)

新: parsing ──→ verifying(等待窗≤45s)──→ analyzing → report(带 sandbox_indicators) → complete
    │           └ 超时 fail-soft: 已完成的进 report, 未完成取消
    └ 提交与解析并行启动 (submit 秒级, 解析毫秒级)
```

## 3. 验证内容升级 (从数值字段 → 页面语义)

`verify_urls` 单条 URL 产出新增:

1. **DOM 获取**: `GET https://urlscan.io/dom/{uuid}/` (免费档可得, 实测校准)
2. **密码表单静态检测 (零 LLM, 确定性层)**: DOM 正则
   `input[type=password]` 存在性 + `<form action>` 域与页面域比对 —
   "有密码框 + 提交到异域/子域" 是强信号; 与 email_triage 确定性信号同哲学
3. **视觉 LLM 语义判定**: 截图 (base64) 喂 router 模型 (复用截图转写同机制),
   问三件事: 页面声称什么身份? 是否索取凭据? 表单提交到哪?
   输出结构化: `{claimed_identity, credential_form, submits_to, impersonation_verdict, confidence}`
4. **ASN 偏离** (弱信号, 展示用): page.asn 与主域常见 ASN 不比对 (无库),
   仅展示解析 IP/ASN 供人工判断 — 不自动化, 避免误报

单条 URL 的语义判定结果 (确定性表单检测 + LLM 判定) 汇成 `sandbox_indicators`,
两路消费: ① 进 LLM 研判上下文 ② 进最终报告渲染。

## 4. LLM 研判注入

- `analyze_email(raw_email, note, sandbox_evidence: str = "")`:
  sandbox_evidence 非空时在 _USER_TMPL 的确定性信号块后追加:
  ```
  【链接沙箱验证 (第三方代访, 已验证事实)】
  - http://x.com: 页面声称「XX 统一身份认证」且含密码表单, 提交至异域 y.com — 高度疑似仿冒登录页 (置信 85%)
  ```
- 系统提示补一条纪律: 沙箱验证块与确定性信号同等对待 (已验证事实, 直接采纳)
- LLM 可引用 sandbox 证据作为 indicator (evidence 用落地页事实, 包含性
  校验的 haystack 需扩展 sandbox_evidence 文本)

## 5. SSE 事件契约 (v2)

| 事件 | 时机 | 变化 |
|------|------|------|
| parsing | 同现 | auto_verify 含义不变 |
| verifying | analyzing **之前** | 消息注明"等待 ≤45s, 超时自动跳过" |
| analyzing | 验证窗结束 | report 事件的 result 新增 `sandbox_indicators: [{url, form_detected, claimed_identity, submits_to, impersonation, confidence, screenshot}]` |
| complete | 收尾 | link_report 仅在**部分超时取消**时仍发 (标注未参与研判); 全部完成时不发 (信息已在 report) |

超时语义: 45s 窗口到期, 已完成的 verdicts 进 report; 未完成的任务取消,
该批以 status=cancelled 发 link_report (前端显示"超时未参与研判"), 不阻塞。

## 6. 前端改动

- 流水顺序: verify 阶段移到 analyze 之前 (HTML 阶段卡换位)
- verifying 事件: verify active (在 analyzing 前)
- analyzing 到达: verify done (auto_verify 时) / skip (未启用)
- report 的 sandbox_indicators: 信号卡渲染 (徽章"沙箱验证", 声称身份/
  表单/提交目标/仿冒判定), 与确定性信号、语义依据并列
- link_report (超时态): 卡片标注"超时未参与研判"
- 验证卡区保留 (落地 URL/评分/域名年龄/截图), 数据源改为 sandbox_indicators

## 7. OPSEC 与边界

1. 依然零接触: 截图/DOM 由 urlscan 沙箱产出, httpx 只打 urlscan.io;
   密码表单检测在本地对 urlscan 返回的 DOM 做
2. 截图发视觉 LLM (智谱) — 与邮件原文进 LLM 同类第三方处理, 一致性可接受,
   spec 明示
3. 语义判定结果标注置信度, UI 注明"概率性线索" — 不冒充确定性结论
4. 免费档额度: 每封邮件 ≤3 条 submit 不变; 429/失败 fail-soft 不变

## 8. 文件改动清单

| 文件 | 改动 |
|------|------|
| `app/security/link_verifier.py` | DOM 获取 + 密码表单检测 + 截图拉取 + `_judge_landing_page` 视觉判定; verify_urls 返回扩展 |
| `app/security/email_triage.py` | analyze_email 加 sandbox_evidence; 系统提示纪律; haystack 扩展 |
| `app/api/v1/secops.py` | SSE 重排: 并行提交 + 45s 等待窗 + report 带 sandbox_indicators + 超时 link_report |
| `frontend/index.html` + `email.js` + `styles.css` | 阶段换位 + sandbox 信号卡 + 事件适配 |
| `tests/test_link_verifier.py` | DOM/表单检测单测 + LLM 判定 mock + SSE 新序列两态 |

## 9. 验收标准

1. 有 key 正常路径: start→parsing→verifying→analyzing→report(sandbox_indicators
   非空)→complete; LLM 上下文含沙箱证据 (mock 断言)
2. 超时路径: report 无 indicators, link_report 标 cancelled, complete 正常
3. 无 key: 与现状一致 (verifying 不发, verify 阶段 skip)
4. 密码表单检测: DOM 样例 (有/无密码框、同域/异域 action) 四象限单测
5. 真实案例回归: newcas.gzhu.edu.cn 类 (合法域+仿冒页) 语义判定能给出
   仿冒结论而 score=0 不再误导 (以模拟 DOM/截图单测为准, 不重复提交真实目标)
