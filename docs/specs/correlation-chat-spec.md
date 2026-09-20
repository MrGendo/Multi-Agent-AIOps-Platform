# 对话式告警关联研判 (Correlation Chat) — 契约任务书

## 目标
用户在聊天框不断粘贴/输入多条告警（或描述观察），每轮 agent 按需调工具取证（照常透出工具调用事件）；任意时刻点「生成关联报告」把会话内全部告警做攻击链关联总结，出统一 incident 报告（verdict/severity/攻击链/证据引用/处置建议）。

## 新文件
1. `app/security/correlation.py` — 核心模块
2. `app/api/v1/secops.py` — 追加 3 个端点（见下）
3. `frontend/index.html` + `app.js` — 关联研判模式 UI
4. `tests/test_secops_correlation.py` — 离线单测

## 1. app/security/correlation.py 契约

### CorrelationSession (dataclass, 持久化到 data/secops_correlation/{cid}.json)
```python
cid: str                       # 会话 id (corr-<ts>-<rand4>)
created_at: str                # ISO
alerts: list[CorrAlert]        # 累积的告警
turns: list[CorrTurn]          # 对话轮 (role: user/assistant, content, tools_used: list[str], ts)
last_summary: str              # 最近一轮关联摘要 (assistant 输出)
status: str = "active"         # active / reported
report: dict | None = None     # 生成报告后填充
```
CorrAlert: `raw: str, source: str = "", src_ip: str = "", ts: str = ""` (从文本提的 IOC 用 ioc_extractor.extract_iocs)
CorrTurn: `role: str, content: str, tools_used: list[str], ts: str`

### 异步函数
```python
async def correlation_turn(cid: str, user_input: str, *, emit) -> dict:
```
- emit: async callable(type, data) — 每步透出事件: `corr_tool_call` / `corr_assistant` / `corr_alert_added` / `corr_error`
- 流程: ① 提取本条输入的 IOC (extract_iocs) → CorrAlert 追加, emit corr_alert_added
  ② 构建 prompt (系统提示 + 全部累积告警 + 近期对话摘要(复用 dialogue 滚动压缩思想, 近6轮原文/早期摘要) + 当前输入)
  ③ LLM ReAct: bind_tools(INVESTIGATOR_TOOLS) 循环 ≤3 轮, 每次工具调用 emit corr_tool_call{name, args, result 截断 300 字}
  ④ 最终 structured output: CorrelationAnswer(verdict_estimate: str 四态, confidence: float, summary: str 关联摘要, correlation_points: list[str] 本轮发现的关联点, next_hints: list[str] 建议下一步)
  ⑤ 写 CorrTurn, 返回 answer dict

```python
async def generate_correlation_report(cid: str, *, emit=None) -> dict:
```
- 输入: 会话全部告警+对话+工具发现
- structured output: CorrelationReport(verdict: str, severity: str, confidence: float, attack_chain: list[str] 按时间/逻辑排序的攻击阶段, correlations: list[dict] 每条 {alerts_involved: list[int], link: str} 告警间关联, mitre: list[str], key_evidence: list[str], response_actions: list[str], conclusion: str)
- status → "reported", report 落库, 返回报告 dict
- 复用 untrusted.py 包裹告警原文 (防注入, 同 analyst)

### 持久化
- save/load 同 dialogue.py 模式 (json, SESSIONS_DIR 兄弟目录 data/secops_correlation/)
- list_sessions(limit=20) 返回 cid/created_at/alerts 数/status/verdict 概要
- 已 reported 的会话点「再补一条」自动开新会话? 不: status=reported 后 correlation_turn 拒绝并提示 (简化)

### 工具池
复用 `app.security.investigator.INVESTIGATOR_TOOLS` + `_get_tool` — 同款只读池 (dns/ping/http/web_search)。工具调用走 `app.runtime.tool_runner._safe_invoke_tool(tool, {"name":..., "id":..., "args":...})` — **id 必传** (UI E2E 抓过 KeyError('id') 坑)。

### LLM
- get_chat_llm(temperature=0, timeout=120, max_retries=3) (GLM 慢窗口, analyst 同款)
- ainvoke_structured(schema_cls, messages, model_name=None) — 同 analyst 导入方式: `from app.core.structured import ainvoke_structured`

### 事件类型 (emit 的 type)
- `corr_alert_added` {cid, alert_index, raw 截断 200, iocs 摘要}
- `corr_tool_call` {cid, name, args 摘要, result 截断 300}
- `corr_assistant` {cid, answer dict}
- `corr_report` {cid, report dict}
- `corr_error` {cid, message}

## 2. API 端点 (app/api/v1/secops.py 追加)
```
POST /api/v1/secops/correlation                # 开会话/追加一轮 {cid?: str, message: str} → SSE 流 (event types 同上)
GET  /api/v1/secops/correlation                # 会话列表
GET  /api/v1/secops/correlation/{cid}          # 会话详情
POST /api/v1/secops/correlation/{cid}/report   # 生成关联报告 → SSE 流 (corr_report 事件) 或 JSON (accept: application/json)
```
- SSE 用 EventSourceResponse yield dict 事件 (平台惯例, 勿 yield 预格式化字符串 — 静默吞)
- POST body Pydantic: CorrelationRequest{cid: str = "", message: str}
- 无 cid 时服务端生成 corr-<ts>-<rand>

## 3. 前端 (安全研判 tab 内加「关联研判」子模式)
- 现有研判输入框上方加模式切换: [单条研判 | 关联研判] 双态 (你的双态偏好, 不加多余按钮)
- 关联模式: 复用对话式 UI 骨架 — 上方聊天流 (user 右/assistant 左, 每条 assistant 消息下方列 tools_used chips), 下方输入框+发送, 右上「生成报告」按钮 (会话 ≥1 轮才亮)
- SSE 消费: corr_alert_added → 聊天流插「已收录第 N 条告警」系统行; corr_tool_call → 插工具调用卡 (name+args+result 折叠, 样式复用 secops-findings 工具卡); corr_assistant → 插 assistant 消息; corr_report → 渲染报告区 (attack_chain 时间线样式, correlations 卡片)
- 报告区底部: [复制] [导出 .md] 两按钮 (同时满足 c 项报告导出, SecOps 报告通用能力)
- 成本行: 每次研判/每轮对话后显示 耗时 + LLM 调用次数 (服务端在 complete/corr_assistant 事件里带 llm_calls + elapsed_ms 字段, 前端底部小字显示)

## 4. 处置登记 (a 项, 复用本 UI)
- 单条研判报告区底部三按钮: [已处置] [误报] [搁置] → POST /api/v1/secops/{session_id}/disposition {action, note} (session_id 用 triage session id; 无会话的 triage 用 alert_history 最后一条的 id)
- 落 alert_history.jsonl (disposition 字段) + consolidation 沉淀管线照常吃
- 关联会话的报告生成后同样三按钮 (cid 维度)

## 5. 跨域反向提示 (d 项)
- app/agents 报告后处理: 诊断报告文本出现安全特征词 (挖矿|后门|webshell|可疑外联|爆破|恶意进程|反向 shell) 时, SSE 追加一条 `cross_domain_hint` 事件 {type: "security", reason, suggestion: "疑似安全事件, 建议移交安全研判"}
- 前端诊断报告区顶部渲染提示条 + 「转安全研判」按钮 (点击把诊断摘要预填进 secops 输入框并切换 tab)
- 只提示不自动转 (避免误判循环)

## 6. 测试 (tests/test_secops_correlation.py)
- CorrAlert/会话持久化 round-trip
- correlation_turn: monkeypatch LLM (FakeLLM 带 bind_tools 同款桩) + monkeypatch _safe_invoke_tool → 验证事件序列 [corr_alert_added, corr_tool_call, corr_assistant] + answer 字段
- 工具失败退化: _get_tool 返回 None → 事件仍完整不炸
- generate_correlation_report: monkeypatch ainvoke_structured → 报告字段/落库/status
- 注入防御: 告警文本含「忽略之前指令」→ untrusted 包裹后进入 prompt 的文本含 <untrusted 标记
- 离线全绿 (无真实 LLM)

## 验收 (我做, 不委托)
- 全量 pytest 绿
- 服务重启后真实 E2E: 聊天框连输 3 条相关告警 (同 src_ip 不同设备) → 每轮工具调用事件透出 → 生成报告 → 攻击链/关联点/报告导出 .md 真下载
- UI 真实按钮: 模式切换/发送/生成报告/处置登记/导出 (CDP 直驱, Chrome 9222 已在)

## 边界与风格
- 全部中文注释/日志, 项目既有风格 (loguru logger, ruff clean)
- 不动存量 triage/dialogue 代码路径, 纯新增模块+端点
- Pydantic v2 Field 风格, description 必写
- frontend 无构建步骤, 原生 JS (app.js 单文件追加函数, index.html 追加区块)
