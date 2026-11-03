# 邮件研判沉淀 (健康审查批 4) 设计规格

日期: 2026-11-03
状态: 待审批
前置: docs/project-health-review-2026-11-03.md §1.1 (邮件研判零沉淀)
参照: 告警侧三件套 (alert_history.jsonl + consolidation 经验库 + sigma_forge)

## 1. 问题

邮件管线 (/email/triage) 判完即弃: 无历史、无经验提炼 — 同样的钓鱼模式再来一封,
系统不记得见过; 人工也无法回溯"这个发件域之前判过几次"。告警侧三件套在邮件侧一件都没有。

## 2. 方案 (对齐告警侧模式, 按邮件形态裁剪)

### 2.1 历史落盘 — `app/security/email_history.py` (新)

- `append(record)` / `query(limit)` / `sender_domain_stats(domain, days)`:
  `data/email_history.jsonl` 逐行 append, 记录: 时间 / 发件域 / From / Subject 摘要 /
  classification / phishing_type / confidence / 提取的 URL 域 / degraded 标记
- **闭环用途 (不止存档)**: 研判前查**同发件域近 90 天历史判定**, 作为已验证事实
  注入 LLM 上下文 —「该发件域 30 天内已有 3 次 phishing 判定 (最近 2026-11-01)」,
  复发攻击判定直接受益
- 解析循环节俭: 本模块内实现一次, 不再复制到别处 (健康审查 3.2 的教训)

### 2.2 经验提炼 — `consolidation.py` 扩展 `consolidate_email_verdict`

- 触发: classification == phishing 且非 degraded (benign/suspicious 不入库,
  与告警侧「无沉淀价值不入库」同纪律 — 防噪声)
- 内容: LLM 把 EmailVerdict 提炼为威胁模式文档 (攻击话术/仿冒手法/诱饵特征/
  鉴别要点), `source=email_experience` 入 Milvus, 复用 split_markdown + 补 h1/h2/h3
  (缺键被静默丢弃的教训)
- 召回: 邮件研判时向量召回同类经验, 注入 LLM 参考 (与告警侧 recall 同模式);
  **标注为参考而非依据** — 健康审查/评测 4.2 的教训, prompt 里明示经验仅供参考
- 去重: 不做 (重复研判同一封邮件是低频人工操作; Milvus 无内容去重通道),
  治理由批 3 的 /experience/delete 兜底

### 2.3 注入与执行点 — SSE 流不变

- 事件序列**零变化** (start→parsing→verifying→analyzing→report→complete):
  历史查询在 analyze_email 前 (毫秒级 jsonl 尾读), 经验召回并行于确定性解析,
  两者并入既有「已验证事实」注入通道 (与 sandbox_evidence 同格式拼装)
- consolidate 在 complete 后 fire-and-forget task (fail-soft, 不阻塞流;
  不纳入 SSE finally 取消链 — 它本来就该在断连后仍完成沉淀)
- 前端不动: 查询走新端点 `GET /email/history?limit=20` (整理起来 = 可查)

### 2.4 明确不做

- **Sigma 反哺**: Sigma 是日志/网络检测规则形态, 邮件钓鱼的对应物是网关规则/
  YARA — 为对称而对称属过度工程, 不做
- 前端历史 UI: 后端 API 可查即闭环, UI 等有真实回溯需求再做
- 邮件研判对话/关联会话: 无需求信号

## 3. 文件改动

| 文件 | 改动 |
|------|------|
| `app/security/email_history.py` (新) | append/query/sender_domain_stats + 尾读 |
| `app/security/consolidation.py` | + consolidate_email_verdict (LLM 提炼 + 入库) |
| `app/security/email_triage.py` | analyze_email 内注入历史事实 + 经验参考 (参数化, 无 key/无记录时行为与现状一致) |
| `app/api/v1/secops.py` | SSE: 注入调用 + complete 后 consolidate task; + GET /email/history |
| `tests/test_email_history.py` (新) | append/query/域统计/尾读 |
| `tests/test_email_triage.py` 扩展 | 注入断言 (mock) + SSE 序列不变 |

## 4. 验收标准

1. 无历史/无经验时: 事件序列与判定行为与现状一致 (回归保障)
2. 同域二次研判: LLM 上下文含该域历史判定计数 (mock 断言), 复发邮件判定
   置信度应高于首见 (真实跑观察项, 不作硬断言)
3. phishing + ok 判定 → email_experience 入库; benign 不入库; LLM 失败 fail-soft
4. GET /email/history 返回最近记录; /experience/delete 可治理 email_experience
   (source 过滤已天然支持)
