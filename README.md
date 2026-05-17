# Multi-Agent AIOps Platform

面向 OnCall / SRE 场景的智能运维多智能体诊断系统。

本项目基于 `FastAPI`、`LangGraph`、`Milvus`、`FastMCP` 和大模型（DeepSeek / DashScope）构建。系统彻底摒弃了传统单体大模型的线性诊断思维，采用高度分形化的 **Orchestrator-Experts-Merger (统筹-多专家-汇编)** 拓扑架构。它具备从历史经验库自主召回诊断路径、在沙箱中动态编写 Python 代码探测、防幻觉底层微观校验，以及跨技术域（如网络、数据库、宿主机等）并行联合排障的完整闭环能力，构筑了高阶、安全、可落地的自动化运维中枢。

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-green)
![LangGraph](https://img.shields.io/badge/LangGraph-Agent-orange)
![Milvus](https://img.shields.io/badge/Milvus-VectorDB-purple)
![FastMCP](https://img.shields.io/badge/FastMCP-Tools-black)

---

## 核心功能全景

本项目实现了对传统运维自动化工具的降维打击，具备以下高阶特性：

1. **精准分发与防重复的多专家并行会诊**
   针对复杂的跨域故障，系统能**并发**拉起网络、数据库、主机等多个专门领域的独立专家（Agent）分别诊断。为防止资源浪费与操作重叠，系统在路由侧实现了极严苛的“防过度扇出”机制（绝大多数单点故障只唤醒 1 个最核心专家）。
2. **“经验大脑”双路检索机制 (Dual-RAG)**
   告警发生的第一时间，系统不会盲目排查，而是从 Milvus 向量数据库并行唤醒两路记忆：一是标准的运维手册/SOP（静态知识），二是该系统过往真实排障留下的成功案例报告（动态实战经验），从而实现“越用越聪明”。
3. **动态沙箱编程 (Dynamic Code Sandbox)**
   突破了固化 API 的死板限制。如果内置工具无法采集所需指标（如需要构造特定网络包），大模型会当场编写一段专属的 Python 脚本，并置入完全隔离的安全子进程 (Subprocess) 中执行，大幅度拓展了诊断边界。
4. **零信任机密注入 (SecretVault)**
   在动态编程诊断时，大模型的上下文中绝不出现真实密码（如 MySQL/Redis 凭据）。大模型仅被允许使用特定占位符（如 `os.environ.get("SECRET_MYSQL_PASS")`），底层框架在子进程拉起的一瞬间将真实密码作为环境变量注入，实现金融级的全链路防泄露。
5. **底层防幻觉微观校验 (Critic)**
   每个专家执行完一次探测后，其原始输出（终端报错日志、命令结果）都会由专门的审计节点（Critic）进行无情审查。只要存在捏造数据、未调用工具或脚本执行抛出异常（如 SyntaxError），系统会当即驳回让大模型重写，斩断“幻觉链条”。
6. **防死循环重规划 (Replanner)**
   严格监控历史执行路径，内置了代码级和 Prompt 级的双重“复读机拦截”逻辑。如果大模型企图再次执行刚才已做过的完全相同的步骤，平台将强行阻断并驱动其立刻输出结论，杜绝 Token 空耗。
7. **全链路 SSE 实时可视化反馈**
   前端通过 Server-Sent Events (SSE) 实时渲染系统的工作进度：从并行专家调度、每一小步的思考规划、工具调用、沙箱状态到最终报告聚合，全部以结构化的打字机流式输出，掌控感极强。
8. **自愈决策与人机共驾 (HITL)**
   完成全域诊断并输出根因后，系统会拟定具体的自愈变更步骤（如自动杀进程、扩容），在正式执行前引入 Human-In-The-Loop（人机回路）触发审批停顿，确认后通过 Action Executor 收尾。

---

## 核心设计与模块实现

### 整体架构设计图

系统核心诊断图由 LangGraph 编排驱动，架构如下图所示：

```mermaid
flowchart TD
    A[User Input / Alertmanager Webhook] -->|1. 触发诊断| B[Orchestrator 统筹节点]
    
    subgraph "经验大脑 (RAG/Milvus)"
    RAG[(experience_db & kb_corpus)] -.->|2. 检索双路上下文| B
    end

    B -->|3. LangGraph Send 并发扇出| E1(Database Expert)
    B -->|3. LangGraph Send 并发扇出| E2(Network Expert)
    B -->|3. LangGraph Send 并发扇出| E3(...)
    
    subgraph "Expert Subgraph (领域专家独立子图)"
    E1 --> P[Planner 节点: 拆解探测步骤]
    P --> EX[Executor 节点: 调工具/沙箱动态编程]
    
    EX <-->|4. 动态凭据注入| Vault[(Secret Vault)]
    
    EX --> C{Critic 节点: 防幻觉/报错校验}
    C -->|5. 驳回要求重改| EX
    C -->|6. 校验放行| RP[Replanner 节点: 宏观裁定]
    RP -->|需补充证据| EX
    end

    RP -->|7. 独立报告提交| M[Merger 汇编节点]
    E2 --> M
    E3 --> M
    
    M -->|8. 消除冲突合成主报告| RM[Remediation Planner 自愈规划]
    RM -->|9. 人工审批停顿 (HITL)| AE[Action Executor 自愈执行]
    
    AE -->|10. 诊断报告输出| Output[SSE 推送前端 & 异步提炼入库]
```

### 节点作用与底层实现详解

#### 1. Orchestrator (统筹调度者)
- **核心作用**：作为“急诊分诊台”，接收原始故障描述，负责检索历史经验，并精准决策应该唤醒哪些领域的专家。
- **底层实现**：
  - 调用 `DashScope Embedding` 和 `Milvus` 进行 RAG 混合检索（向量相似度 + BM25）。
  - 使用大模型解析 `AgentHarness` 中严苛的分发路由 Prompt，输出包含 `skill_names`（列表格式）的 Pydantic 模型。
  - 使用 LangGraph 的 `Send` API (Map-Reduce 范式) 将输入状态分别广播到目标领域的多个 `Expert Subgraph` 节点，以此实现多个专家状态的物理隔离与并行运算。

#### 2. Planner (局部规划节点)
- **核心作用**：每个被唤醒的领域专家，首先会为自己的调查方向拟定一个 2-3 步的初始探测计划。
- **底层实现**：传入告警信息与当前领域的专属可用 MCP 工具列表（Tool Catalog）。通过大模型的结构化输出机制 (`ainvoke_structured`)，返回一个形如 `{"steps": ["查本机进程", "分析进程日志"]}` 的 JSON 对象。

#### 3. Executor (深度探测与沙箱执行器)
- **核心作用**：真正干脏活累活的模块。它取出 `plan` 的第一步，如果 MCP 内置工具有用就直接调用；如果没有合适工具，则利用 Python 写探测代码。
- **底层实现**：
  - **静态工具流**：如果是常规请求，会通过 `FastMCP` 协议拉起本地或跨机的只读监控探针（如 `psutil`, `docker`）。
  - **动态沙箱流**：如果大模型生成了 ````python ... ```` 代码，Executor 将调用 Python 的 `subprocess.run` 启动独立进程执行。在此阶段，系统会通过环境字典拦截特定变量名（如 `SECRET_` 前缀），从全局配置中提取真实值通过 `env=` 参数打入子进程。

#### 4. Critic (底层防幻觉校验)
- **核心作用**：充当“挑刺”的审核员。阻断大模型虚构排查过程、捏造假数据，以及拦截 Python 语法错误（如 NameError）。
- **底层实现**：在 Executor 跑完一次工具后，Critic 节点用较小的快模型（如 qwen-turbo）快速过审。它的 Schema 强制输出 `is_passed: bool`。如果检测到幻觉或脚本抛错，返回 `is_passed=False` 与具体 `feedback`。LangGraph 中的条件边 `route_after_critic` 会将其强制导流回 Executor 要求其参考 `feedback` 重修代码，直至过审。

#### 5. Replanner (复读机克星与宏观裁定)
- **核心作用**：在每次成功拿到一个监控指标后，评估当前搜集到的所有证据（`past_steps`）是否已经足以定位到自己所管辖领域的根因。
- **底层实现**：
  - 传入历史执行列表，由 LLM 输出 `is_finished: bool` 及剩余 `plan`。
  - **代码级防抖**：代码中强行判断 LLM 吐出的新 `plan` 字符串前 20 个字符是否与刚完成的探测步骤高度雷同，如果是则强制拦截删除，打破大模型由于过于谨慎而造成的同一工具无限循环重试的怪圈。

#### 6. Merger (冲突解决与信息汇编)
- **核心作用**：所有的专家子图收敛（Join）的终点。汇总各个专家提交的片面报告，消除互相矛盾的信息。
- **底层实现**：接收 LangGraph 并行分支归集的 `expert_reports: Annotated[List[str], operator.add]` 状态字段。使用最高级别的推理模型综合全文证据，利用 Pydantic 约束生成包含“现象、证据、根因、建议”的最终统一 Markdown 报告。

---

## 详细数据流转说明

为了清晰呈现，我们将从收到一段告警（如："我的服务器 C 盘满了"）开始，拆解数据的精确流向和形态变化。

### 阶段 1：告警接入与上下文准备 (Input -> RAG)
- **数据来源**：前端输入框发出的 JSON 请求，或 Prometheus/Alertmanager 发来的 Webhook payload。
- **传输过程**：
  1. FastAPI 的 `/api/v1/aiops/diagnose` 接收字符串格式的 `query`。
  2. 系统提取 `query` 送入 DashScope 的 Embedding 模型，转换为 1024 维的高维浮点数组。
  3. 携带该向量请求后端的 `Milvus` 服务，执行 Hybrid Search（混合检索）。
- **输出形态**：Milvus 返回一组 Top-K 的 Markdown 文本字符串，形如 `{"content": "历史案例：C盘占满通常由于 docker/overlay2 导致...", "metadata": {"source": "experience_db"}}`，即为上下文（Context）。

### 阶段 2：统筹路由分配 (Orchestrator -> Send API)
- **输入数据**：`query` + `Context` + 系统的全局专家花名册（String）。
- **处理与流向**：
  1. Orchestrator LLM 对输入进行推理，输出严格约束的 JSON：`{"is_oncall": true, "skill_names": ["host_resource_diagnosis"]}`。
  2. LangGraph 框架捕捉到 `skill_names`，自动创建多个分支副本。每个分支被赋予一个初始 `PlanExecuteState`（LangGraph TypedDict），包含字段 `{"input": query, "selected_skill": "host_resource_diagnosis", "past_steps": []}`。
  3. 这些 State 被分别塞给后端的独立 Worker 线程执行。

### 阶段 3：专家内循环探伤 (Planner -> Executor -> Critic -> Replanner)
*以下数据流在独立的子图内存里飞速流转：*
- **Planner 数据流**：接收 State，输出 Pydantic JSON `{"steps": ["检查磁盘挂载信息", "寻找大于1G的文件"]}`。更新 State 的 `plan` 字段。
- **Executor 数据流**：
  1. 取出 `plan[0]` ("检查磁盘挂载信息")。
  2. 触发 FastMCP 客户端，向本地监听 `http://localhost:8005/mcp` 的工具系统发送 RPC JSON-RPC 请求。
  3. 工具服务返回真实的系统监控数据文本 `df -h output...`。
  4. Executor 收到回包，执行追加动作 `state["past_steps"].append(("检查磁盘挂载信息", "df -h output..."))`。
- **Critic 数据流**：提取刚刚附加的元组，推理后返回 Boolean 标识 `critic_passed: True`。
- **Replanner 数据流**：接收包含大量终端输出的 `past_steps`，发现证据已满，输出 JSON `{"is_finished": true, "response": "## 磁盘爆满根因分析..."}`。此字符串被赋值给 State 的 `response` 并结束当前子图的死循环。

### 阶段 4：前端映射与信息融合 (State -> SSE -> Frontend & Merger)
- **实时传输 (SSE)**：在上述每一个节点产出结果的一瞬间，后端的 `aiops_service.py` 都会使用 `yield` 关键字通过异步生成器抛出一个字典形如 `{"type": "step_complete", "stage": "step_executed", "message": "完成第 1 步"}`。前端 EventSource 实时捕获并按时间线渲染卡片。
- **图汇编流向**：各专家执行终结后，LangGraph 的底座自动将所有专家的 `response` 字段使用 `operator.add` 叠加到全局 State 的 `expert_reports` 列表中，传输至 `Merger` 节点汇总。

### 阶段 5：经验沉淀 (Merger -> Consolidation Worker -> Milvus)
- 最终的排障报告展示给用户后，后端的 `consolidation_worker.py` 会默默发起一个独立异步任务。
- **数据处理**：将最终长达几千字的 Markdown 报告精简提取为“故障模式特征词”与“解决方案”的稠密结构。
- **入库操作**：重新调用 Embedding 将这段核心经验转化为向量，写入 Milvus 的 `experience_db` 中，完成数据链路的最后一块内化拼图。

## 功能特性

- **多专家并行协作 (Orchestrator-Experts)**：从单体模型演进为集群调度，支持多维故障（如 CPU与网络同时异常）的并行诊断，大幅缩短时延。
- **动态工具沙箱编程**：突破静态 API 限制，支持 LLM 在本地安全的沙箱内实时编写、执行 Python 脚本来完成深度探测。
- **Critic 微观幻觉防御**：自带代码执行审计与数据捏造检测机制，保障排障推理链路的绝对真实。
- **零信任机密注入**：引入 `SecretVault`，大模型编写排障脚本时全程通过环境变量占位符获取机密，密码永不进入 LLM 上下文。
- **长期记忆与经验内化**：内置异步 `Consolidation Worker`，诊断完毕后自动提炼底层根因并反哺 Milvus 经验库，实现经验沉淀。
- **Plan-Execute-Replan 流程**：基于局部专家的内部严密闭环，支持基于真实回传证据的动态计划调整。
- **RAG 知识库融合**：使用 DashScope Embedding + Milvus，支持 OnCall SOP、开源 Prometheus 告警语料以及动态历史经验检索。
- **实时 MCP 工具服务**：接入系统信息、网络诊断、Windows 日志、Docker 等只读工具服务。
- **真实 Token 监控与 SSE 流式反馈**：前端实时通过打字机效果呈现系统并行调度、专家思考、沙箱执行等极具科技感的中间态。

---

## 技术栈

| 类型 | 技术与框架实现 |
|---|---|
| Web 服务与 API 层 | **FastAPI** + Uvicorn (全面拥抱 Async/Await 异步并发体系) |
| Agent 编排引擎 | **LangGraph** (实现细粒度状态机、Send API 并发、子图逻辑) |
| 大模型基座 | **DashScope / Qwen** (默认)，基于 OpenAI Compatible API 设计，无缝平替 DeepSeek |
| Embedding 模型 | DashScope `text-embedding-v4` (搭配 GTE-Rerank 实现检索) |
| 向量数据库引擎 | **Milvus** (独立部署，负责核心经验库与 SOP 的召回引擎) |
| 会话记忆系统 | **Redis** (缓存长文本聊天轮次记录) |
| 外部工具与探针 | **MCP / FastMCP** (大模型上下文协议，实现工具调用的去中心化解耦) |
| 联网搜索组件 | **open-webSearch** (利用本地 Docker 部署搜索代理服务) |
| 前端工程 | HTML + **TailwindCSS** + Vanilla JS (追求极速启动与免配置) |
| 运行环境与依赖 | Python 3.11+ / Docker Compose / Windows PowerShell |

---

## 快速部署指南

### 1. 克隆项目与基础环境

```powershell
git clone <your-repo-url>
cd multi_agent_github

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. 关键配置 (.env)

```powershell
copy .env.example .env
notepad .env
```

确保至少填入模型密钥（本项目默认底层针对阿里云百炼模型平台优化，也全面兼容官方 DeepSeek 平台）：
```env
DASHSCOPE_API_KEY=sk-your-dashscope-api-key
KB_ADMIN_TOKEN=change-this-admin-token
```

### 3. 拉起后端基础中间件 (Docker)

一键启动底层依赖库，包含 Milvus 向量引擎及其管控台 (Attu)，以及 Redis 与 open-websearch 引擎。
```powershell
docker compose up -d
```

### 4. 语料初始化入库

这一步极其重要，这为智能体提供了最初的 SOP 认知与检索语料。
```powershell
# 先进行测试切分
python scripts\ingest_kb_corpus.py --dry-run

# 确认正常后正式写入 Milvus 知识库中
python scripts\ingest_kb_corpus.py --reset
```

### 5. 启动总线服务

启动脚本将拉起 1 个 FastAPI 核心主程序 和 4 个 FastMCP 工具监听微服务（本机系统探针、Windows 日志探针、网络诊断探针、Docker 管理探针）。
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run.ps1
```

[ready] open-webSearch is listening on 127.0.0.1:3210
[start] MCP system_server (port 8005)...
[ready] MCP system_server is listening on 127.0.0.1:8005
[start] MCP websearch_server (port 8006)...
[ready] MCP websearch_server is listening on 127.0.0.1:8006
[start] MCP winlog_server (port 8008)...
[ready] MCP winlog_server is listening on 127.0.0.1:8008
[start] MCP network_server (port 8009)...
[ready] MCP network_server is listening on 127.0.0.1:8009
[start] MCP docker_server (port 8011)...
[ready] MCP docker_server is listening on 127.0.0.1:8011
[start] FastAPI main service (port 9900)...
        Web UI:  http://localhost:9900
        API Doc: http://localhost:9900/docs

一切就绪后，直接在浏览器中访问 **[http://localhost:9900](http://localhost:9900)** 即可开启多智能体 AIOps 诊断体验。
要停止全套服务，执行：`powershell -NoProfile -ExecutionPolicy Bypass -File .\run.ps1 -Stop`。

## 项目结构

```text
multi_agent_github/
├── app/                    # FastAPI / Agent / RAG / Skill 核心代码
├── mcp_servers/            # MCP 工具服务
├── frontend/               # 前端页面
├── docs/sop/               # 内置 OnCall SOP
├── data/kb_corpus/         # RAG 开源语料
├── scripts/                # 知识库和告警模拟脚本
├── docker-compose.yml      # Milvus + etcd + MinIO + Attu + Redis
├── requirements.txt
├── .env.example
├── .gitignore
└── run.ps1                 # Windows 一键启动脚本
```

## 性能评估数据

本项目针对运维诊断中重资产 Token 消耗的问题做了专项的底层重构，实测的基准数据如下：

| 核心指标 | 评估情况 |
|---|---:|
| Planner 环节 Prompt 开销 | **下降 93.5%** (`9098 tokens -> 575 tokens`) |
| 诊断全链路 Total Tokens 损耗 | **降低 66.5%** (`11889 -> 3988`) |
| 只读探针工具并行化调度 | **加速 4.88x** (`1.06s 锐降至 0.22s`) |
| RAG 召回能力 (R@3) | 稳定达到 **95.83%** (基于千级别离线文档测试) |

---
## API 概览

开放了标准的 RESTful API 以供第三方报警平台（如 Prometheus / Zabbix）直接调用触发诊断链路。

| 模块 | 请求类型 | 路由路径 |
|---|---|---|
| AIOps 流式诊断 | POST | `/api/v1/aiops/diagnose` |
| Webhook (自动处理告警) | POST | `/api/v1/webhook/alertmanager` |
| RAG 会话 | POST | `/api/v1/chat/stream` |
| 知识库管理 | POST / DELETE | `/api/v1/documents/upload` 及 `{source}` |

*（注：涉及知识库与系统层面的写入调用必须在 HTTP Header 中携带 `X-KB-Admin-Token`）*

## License

本项目核心源码以 **MIT License** 发布。本项目深度借鉴了业界的优秀理念并集成了部分优质开源方案：
- 参考了 [@Kkkirito-123](https://github.com/Kkkirito-123) 核心思路（[Kkkirito-123/mutil-rag-agent](https://github.com/Kkkirito-123/mutil-rag-agent)）。
- 整合了 [@Aas-ee](https://github.com/Aas-ee) 编写的无密钥网络搜索探针 [open-webSearch](https://github.com/Aas-ee/open-webSearch)。
- RAG 基础黄金测试语料来源于社区优秀的规则集合 [samber/awesome-prometheus-alerts](https://github.com/samber/awesome-prometheus-alerts) (CC BY 4.0 许可)。
- 感谢“小林 OnCall Agent”项目为排障大类设计提供的灵感。
