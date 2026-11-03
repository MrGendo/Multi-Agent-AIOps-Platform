# 项目健康审查报告

日期: 2026-11-03
方式: 主会话事实核查(沉淀/治理/流程) + 独立子 Agent 全仓静态审查(冗余/效率/残留)
基线: main @ ad5e9e7

## 总览(按用户六问)

| 问题 | 结论 |
|------|------|
| 历史告警/钓鱼邮件整理起来了吗 | 告警侧**健全**(历史/经验/Sigma 三件套); 邮件侧**零沉淀** 🔴 |
| 有总结经验吗 | 告警侧有完整飞轮(研判→提炼→向量入库→召回参考→Sigma 反哺); 但**经验库无质量治理** 🔴 |
| 流程改进空间 | 深查时延 160-350s 的本地可控部分; 经验压制 payload 的判定风险 |
| 效率优化 | **两个事件循环阻塞硬伤** + 每请求全量重读历史的慢性问题 |
| 冗余代码 | **316 行整文件死代码** + 解析逻辑六处复制 + 三胞胎/小工具簇 |
| 及时清理低质历史 | 清理机制只覆盖 jsonl/会话目录, **Milvus 经验库无清理接口**; data/ 有 9 月残留 |

## 一、🔴 高优先级(正确性/稳定性)

### 1.1 邮件研判零沉淀 (功能缺口)
告警管线有三件套: `alert_history.jsonl`(500KB 历史) + `secops_experience` 经验库
(consolidation.py 提炼入库, context_provider 向量召回, benign 不入库防噪声) +
`sigma_forge` 检测规则反哺。**邮件管线(/email/triage)一样都没有**: 无历史存储、
无经验提炼、无 Sigma — 判完即弃。同样的钓鱼模式再来一封, 系统不记得见过。
建议: 邮件研判结果落 history + phishing 判定提炼经验(沿用 consolidation 模式)。

### 1.2 事件循环阻塞 #1 — threat_intel 同步串行 (threat_intel.py:71-75)
`enrich_iocs` 是 async 函数, for 循环里同步调 `web_search()`(阻塞 httpx.post,
15s 超时) × 最多 8 个 IOC — 最坏把**整个 FastAPI 事件循环卡死约 2 分钟**, 所有
并发 SSE/健康检查停摆。修复: `asyncio.to_thread` + `gather` 并发, 局部小改。

### 1.3 事件循环阻塞 #2 — llm.py 构造期同步 sleep (llm.py:65-76)
`_glm_rate_limit` 用 `time.sleep` 同步睡眠, `get_chat_llm` 被 async 节点直接调用
— 配置 GLM_MIN_REQUEST_INTERVAL_SEC>0 时每次调用阻塞事件循环整个间隔。
且 `_glm_last_call_ts` 无锁有竞态。

### 1.4 经验库无质量治理 (评测实证)
- `milvus.py` 无任何删除接口 — 经验只进不出
- 评测写入的「RFC 保留段=规则测试漂移」经验**实锤永久留存**(写入日志确认,
  无删除通道), 已实证会压制后续同类告警的 payload 证据(评测报告 4.2)
- history_mgmt 清理覆盖 dialogue/correlation/jsonl, **不覆盖 Milvus 经验、
  sigma_drafts、secops_sessions**
建议: 经验条目加 TTL/低命中淘汰 + 「影响判定的经验」人工确认; 至少先给
RFC 那条一个手动删除通道。

## 二、🟠 中优先级(随时间恶化)

| # | 位置 | 问题 | 建议 |
|---|------|------|------|
| 2.1 | context_provider.py:61-79 | 每次研判全量读 500KB jsonl 逐行 parse, 只为最后 200 条; 文件只增不减 | 倒序读尾部 / mtime 缓存 |
| 2.2 | correlation.py:199 / dialogue.py:162 | `_sessions` 进程内注册表只进不出, 长驻服务内存无上界; list_sessions 全目录扫描无缓存 | LRU/TTL 淘汰 |
| 2.3 | 深查时延 | 160-350s: GLM 限流(外因) + Critic 超时重试 + ThreatIntel 502(外因); 修复 1.2/1.3 后本地可控部分收敛 | 见上 |
| 2.4 | 判定质量 | 评测备考两项: 判定非确定性(经验压制) + 外证依赖过重(T10 inconclusive 0.135) | 提示工程调优, 单独立项 |

## 三、🟡 低优先级(冗余/卫生)

| # | 位置 | 问题 |
|---|------|------|
| 3.1 | agents/skill_router.py (178行) + fork_runner.py (138行) | **整文件死代码**(零引用, 已被 orchestrator/expert_node 取代), 前者还携带与 orchestrator.py 逐字相同的 ~90 行 |
| 3.2 | 6+ 个模块 | alert_history 解析循环(read→splitlines→loads→fail-soft)各复制一份: context_provider/asset_graph/coverage_watch/calibration/history_mgmt×2/judgment_regression×2/webhook — 抽 `iter_history_records()` |
| 3.3 | device_adapters/safeline/cef_adapter | `_payload_cls` 惰性导入三胞胎(根因: SecurityAlertPayload 位置导致循环导入)— 挪到 app/schemas/ 根除 |
| 3.4 | 散落 | `_now_iso`×2、`_normalize_severity`×2、URL 正则漂移×2、会话存储四件套×2(correlation vs dialogue)、~150 行 |
| 3.5 | 8 处 | 未使用导入 — `ruff --select F401 --fix` 一键清 |
| 3.6 | data/ | 9 月残留: alert_history.jsonl.bak-e2e(426KB)、secops_correlation 全部 6 会话、secops_sessions 约 10 个 e2e 会话、logs/ e2e 日志 — 可安全清理(**保留 dlg-eval-T01~T10 评测数据**); gitignore 补 `data/*.db-*` 消 git status 常驻噪音 |
| 3.7 | 既有裁量组 | _extract_email_image 重复 / verify_urls 孪生 / email.js 复制 app.js / SSE 双约定 / note 长度 — 已挂账待拍板 |

## 四、做得好的(不用动)

- 告警侧沉淀闭环完整且设计克制(benign 不入库防噪声、处置登记记录永久保护)
- 历史/会话清理有保留策略 UI(TTL + 最近 N 条 + 处置保护)
- 日志有 zip 轮转; fail-soft 纪律贯穿; 测试 458 例全绿
- milvus/LLM client 每次新建属有意设计(隔离), 收益有限不急改

## 五、建议修复顺序

1. **1.2 + 1.3**(事件循环阻塞 — 局部小改, 稳定性立涨)
2. **3.1**(删 316 行死代码 — 零风险) + 3.5/3.6(卫生清理)
3. **1.4**(经验治理 — 至少 RFC 经验删除通道 + TTL)
4. **1.1**(邮件沉淀 — 功能项, 走 SDD)
5. 2.1/2.2(慢性性能)与 3.2-3.4(收敛)择机
