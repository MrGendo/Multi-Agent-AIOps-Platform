"""应用配置管理.

使用 Pydantic Settings 实现:
  - 自动从 .env 加载
  - 类型校验
  - 字段说明 (可生成文档)
  - 单例模式 (整个进程共享一份配置)

设计原则:
  - 所有可变配置走 .env, 代码里不硬编码
  - 字段名小写 + 下划线 (Python 风格)
  - 环境变量大写 (POSIX 风格), 通过 case_sensitive=False 自动匹配
"""

from functools import lru_cache
from typing import Any, Dict

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """应用全局配置."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ==================== 应用基础 ====================
    app_name: str = Field(default="MultiAgentAIOps", description="应用名")
    app_version: str = Field(default="1.0.0", description="应用版本")
    debug: bool = Field(default=False, description="调试模式")
    host: str = Field(default="0.0.0.0", description="监听地址")
    port: int = Field(default=9900, description="监听端口")

    # ==================== DashScope LLM ====================
    dashscope_api_key: str = Field(default="", description="DashScope API Key")
    dashscope_base_url: str = Field(
        default="https://dashscope.aliyuncs.com/compatible-mode/v1",
        description="DashScope OpenAI 兼容模式 URL",
    )
    dashscope_chat_model: str = Field(default="qwen-max", description="Chat 模型")
    dashscope_router_model: str = Field(default="qwen-turbo", description="Router 模型")

    # ==================== DeepSeek (OpenAI 兼容) ====================
    # 当 *_chat_model / *_router_model / agent_planner_model 名字以 "deepseek" 开头时,
    # get_chat_llm 会自动切到 DeepSeek 的 base_url + api_key.
    deepseek_api_key: str = Field(default="", description="DeepSeek API Key (platform.deepseek.com)")
    deepseek_base_url: str = Field(
        default="https://api.deepseek.com",
        description="DeepSeek OpenAI 兼容 URL",
    )
    dashscope_embedding_model: str = Field(
        default="text-embedding-v4", description="Embedding 模型"
    )
    dashscope_embedding_dim: int = Field(default=1024, description="Embedding 向量维度")

    # ==================== Milvus 向量数据库 ====================
    milvus_host: str = Field(default="localhost", description="Milvus 主机")
    milvus_port: int = Field(default=19530, description="Milvus 端口")
    milvus_collection: str = Field(default="multi_agent_kb", description="Collection 名")
    milvus_timeout_ms: int = Field(default=10000, description="连接超时 (毫秒)")

    # ==================== RAG 基础 ====================
    rag_top_k: int = Field(default=3, description="最终送给 LLM 的 top-k 文档数")
    rag_chunk_size: int = Field(default=800, description="文档分块大小 (字符)")
    rag_chunk_overlap: int = Field(default=100, description="分块重叠大小 (字符)")
    kb_admin_token: str = Field(default="", description="知识库上传/删除管理员 Token")

    # ==================== RAG Chat 会话记忆 ====================
    redis_url: str = Field(default="redis://localhost:6379/0", description="Redis 连接地址")
    rag_chat_memory_enabled: bool = Field(default=False, description="是否启用 RAG Chat Redis 会话记忆")
    rag_chat_history_turns: int = Field(default=3, description="回答时注入最近 N 轮对话")
    rag_chat_memory_ttl_sec: int = Field(default=604800, description="RAG Chat 会话记忆 TTL 秒数")
    rag_chat_rewrite_enabled: bool = Field(default=True, description="是否启用多轮问题改写")
    rag_chat_compact_enabled: bool = Field(default=True, description="是否启用长会话摘要压缩")
    rag_chat_max_messages: int = Field(default=12, description="超过多少条消息触发 compact")
    rag_chat_compact_keep_messages: int = Field(default=6, description="compact 后保留最近多少条原文消息")
    rag_chat_summary_max_chars: int = Field(default=1200, description="会话摘要最大字符数")
    rag_chat_max_tool_rounds: int = Field(
        default=3,
        description=(
            "RAG Chat 工具回合最大轮次. LLM 调一次工具拿数据回来再总结算 2 轮; "
            "调多组工具串行追问算更多轮. 默认 3 轮足够'看一眼系统再回答'的场景."
        ),
    )
    rag_chat_web_search_enabled: bool = Field(default=False, description="是否允许 RAG Chat 使用受限联网搜索")
    rag_chat_web_search_max_results: int = Field(default=3, description="RAG Chat 联网搜索最大结果数")
    rag_chat_web_search_keywords: str = Field(
        default=(
            "redis,mysql,postgresql,mongodb,elasticsearch,kafka,rocketmq,rabbitmq,"
            "nginx,linux,docker,kubernetes,k8s,prometheus,grafana,jvm,java,python,"
            "go,nodejs,fastapi,langchain,langgraph,milvus,etcd,minio"
        ),
        description="RAG Chat 允许触发联网搜索的技术主题词, 英文逗号分隔",
    )

    # ==================== RAG 高级检索 (Hybrid Search + Reranker) ====================
    # 设计思路: 业界主流 "先 Hybrid 提 recall, 再 Reranker 提 precision" (Anthropic
    # Contextual Retrieval / bswen 2026 实测). 任一组件故障都会自动降级到纯向量,
    # 不影响基础功能. 全部默认开启, 通过 .env 关闭便于 A/B 对比.
    rag_retrieve_k: int = Field(
        default=20,
        description=(
            "送进 Reranker 前的候选数 (BM25 + Vector 各取这么多). "
            "为什么 20: Anthropic 实验显示 top-20 是准确率与延迟的平衡点; "
            "局限: 数值越大 rerank 延迟越高, 数值越小 reranker 发挥空间越小."
        ),
    )
    rag_hybrid_enabled: bool = Field(
        default=True,
        description=(
            "是否启用 Hybrid Search (BM25 + Vector + RRF 融合). "
            "为什么: 纯向量漏精确关键词 (服务名/错误码/数字), BM25 正好互补; "
            "局限: BM25 索引是进程内存, 多副本部署需各自构建, 新上传文档需手动或定时刷新."
        ),
    )
    rag_hybrid_bm25_weight: float = Field(
        default=0.4,
        description=(
            "Hybrid 融合中 BM25 的权重 (Vector 权重 = 1 - 该值). "
            "为什么 0.4: 语义占主导, 关键词作补充; 局限: 最优权重依赖语料, 需用 eval 脚本调优."
        ),
    )
    rag_rerank_enabled: bool = Field(
        default=True,
        description=(
            "是否启用 Reranker (DashScope gte-rerank-v2). "
            "为什么: 向量相似度 ≠ 问答相关性, reranker 是 cross-encoder 能精细打分; "
            "局限: 每次查询多一次 API 调用 (约 100-300ms), 网络故障时会自动降级."
        ),
    )
    rag_rerank_model: str = Field(
        default="gte-rerank-v2",
        description=(
            "DashScope Rerank 模型名. "
            "为什么默认 gte-rerank-v2: 多语言 + 长文本友好 + 与本项目 embedding 同家族; "
            "局限: 每月有免费额度, 超量计费."
        ),
    )
    rag_rerank_timeout_sec: float = Field(
        default=8.0,
        description="Rerank API 超时秒数. 超时即降级到纯向量结果, 不阻塞用户."
    )
    rag_bm25_refresh_on_upload: bool = Field(
        default=True,
        description=(
            "文档上传后是否立即重建 BM25 索引. "
            "为什么开: 小规模知识库重建毫秒级, 体验好; "
            "局限: 知识库很大 (10 万 chunks+) 时应改为定时刷新."
        ),
    )

    # ==================== MCP 远程工具 ====================
    # 本机诊断 MCP (都是真实数据源)
    mcp_system_transport: str = Field(default="streamable-http", description="本机系统 MCP 传输")
    mcp_system_url: str = Field(default="http://localhost:8005/mcp", description="本机系统 MCP URL (psutil)")
    mcp_websearch_transport: str = Field(default="streamable-http", description="联网搜索 MCP 传输")
    mcp_websearch_url: str = Field(default="http://localhost:8006/mcp", description="联网搜索 MCP URL")
    mcp_winlog_transport: str = Field(default="streamable-http", description="Windows 事件日志 MCP 传输")
    mcp_winlog_url: str = Field(default="http://localhost:8008/mcp", description="Windows 事件日志 MCP URL")
    mcp_network_transport: str = Field(default="streamable-http", description="网络诊断 MCP 传输")
    mcp_network_url: str = Field(default="http://localhost:8009/mcp", description="网络诊断 MCP URL")
    mcp_docker_transport: str = Field(default="streamable-http", description="Docker 管理 MCP 传输")
    mcp_docker_url: str = Field(default="http://localhost:8011/mcp", description="Docker 管理 MCP URL")

    # ==================== Agent ====================
    agent_max_steps: int = Field(default=5, description="Plan-Execute 最大步骤 (防死循环)")
    agent_max_reroutes: int = Field(
        default=1,
        description=(
            "Replanner 触发 Skill reroute 的最大次数 (防 Skill 之间反复横跳). "
            "业界主流 (LangGraph Supervisor + Handoff) 通常设 1-2."
        ),
    )
    agent_reroute_min_past_steps: int = Field(
        default=2,
        description=(
            "允许触发 Skill reroute 的最小已执行步数. "
            "证据不足时 (past_steps < 该值) 即使 LLM 想切也会被阻止."
        ),
    )
    agent_max_concurrency: int = Field(default=2, description="AIOps Agent 最大并发诊断数")
    rag_max_concurrency: int = Field(default=5, description="RAG Chat 最大并发请求数")
    guardrails_block_high_risk_tools: bool = Field(
        default=True,
        description="是否默认拦截高风险写操作工具",
    )
    guardrails_allow_notification_tools: bool = Field(
        default=True,
        description="是否允许通知类工具",
    )
    mcp_lazy_tools_enabled: bool = Field(
        default=False,
        description=(
            "是否启用 MCP Lazy Tools 两阶段发现/执行. "
            "默认关闭: MCP 工具直接 bind 给 LLM, 单轮即可调用, 减少额外 LLM round. "
            "仅在 MCP 工具数量很大、需要按需暴露时才开启."
        ),
    )
    permission_mode: str = Field(
        default="normal",
        description=(
            "§1 cc-haha 借鉴, 工具权限模式. 取值: "
            "read_only (只允许只读工具) / normal (默认, Skill 白名单+高危黑名单) / "
            "ask_destructive (写工具走人工审批, MVP 暂转 deny) / bypass (dev only, 跳过非硬墙检查). "
            "可被 state.permission_mode 单次会话覆盖."
        ),
    )
    executor_parallel_enabled: bool = Field(
        default=True,
        description=(
            "Executor 是否启用 read-only 工具并行编排 (§3 cc-haha 借鉴). "
            "True 走 run_parallel_agent (按 ToolMeta.concurrency_safe 切批 gather), "
            "False 回退 langchain.agents.create_agent (默认串行, 用于排错对比)."
        ),
    )
    executor_max_iters: int = Field(
        default=4,
        description="Executor 单步内 LLM <-> tool 往返上限 (防 LLM 死循环调用工具)",
    )
    executor_max_parallel: int = Field(
        default=6,
        description="Executor 单批工具并行上限 (cc-haha 默认 10, OnCall 保守取 6)",
    )
    agent_executor_model: str = Field(
        default="",
        description=(
            "Executor 使用的模型. 留空则走 dashscope_chat_model. "
            "建议接 deepseek-v4-flash 之类的快模型: Executor 每步都要 LLM, 跑得最频繁, "
            "用 pro 会非常慢. 报告综合那一步用 pro 最划算."
        ),
    )
    agent_report_model: str = Field(
        default="",
        description=(
            "最终报告合成使用的模型. 留空则走 dashscope_chat_model (推荐 pro). "
            "Replanner 用 flash 做快速决策, 决策 is_finished=true 后再用 report_model "
            "单独写一份高质量的 5 段 SRE 报告, 质量 / 速度两头兼顾."
        ),
    )
    agent_planner_model: str = Field(
        default="",
        description=(
            "Planner / Replanner 使用的模型. 留空则走 dashscope_router_model (qwen-turbo). "
            "结构化输出 (Plan/Act) 不需要大模型, 用 router_model 可减少 60-80% 时延. "
            "想换回 qwen-max 填 'qwen-max' 即可."
        ),
    )
    agent_replanner_fast_path_threshold: int = Field(
        default=2,
        description=(
            "Replanner 快路径门槛: 当 plan 剩余步数 >= 该值且上一步未失败时, "
            "跳过 Replanner LLM 直接进入下一步. 设为 0 则禁用快路径 (每步都 replan)."
        ),
    )
    agent_replanner_past_step_chars: int = Field(
        default=2000,
        description=(
            "Replanner prompt 中每条 past_step result 的字符上限. "
            "防止全量历史 (尤其工具返回 10KB+) 把 LLM 上下文撑爆, 也提速."
        ),
    )
    harness_max_total_tokens: int = Field(default=0, description="单次 Harness run 的总 token 硬上限, 0 表示不限制")
    harness_max_total_ms: int = Field(default=0, description="单次 Harness run 的总耗时硬上限, 0 表示不限制")
    harness_budget_warn_ratio: float = Field(default=0.8, description="达到预算比例后输出 warning 事件")

    # ==================== 联网搜索 ====================
    # provider 可选: open_websearch (本地 daemon, 无 API Key) / mock / ddgs (国内不稳)
    web_search_provider: str = Field(
        default="open_websearch",
        description="联网搜索 provider: open_websearch / mock / ddgs",
    )
    open_websearch_base_url: str = Field(
        default="http://127.0.0.1:3210",
        description="open-webSearch 本地 daemon 地址",
    )
    open_websearch_engine: str = Field(
        default="bing",
        description="open-webSearch 默认搜索引擎, 如 bing / baidu / duckduckgo / startpage",
    )
    open_websearch_search_mode: str = Field(
        default="auto",
        description="open-webSearch 搜索模式: request / auto / playwright",
    )
    open_websearch_timeout_sec: float = Field(
        default=15.0,
        description="open-webSearch HTTP 调用超时秒数",
    )

    # ==================== Docker 管理 ====================
    docker_allow_restart: bool = Field(
        default=False,
        description="是否允许 Agent 调用 docker_restart (危险写操作, 默认禁用)",
    )

    # ==================== 本地 LLM 兜底 (断网/无 API key 时使用) ====================
    local_llm_enabled: bool = Field(
        default=False,
        description="是否启用本地 LLM 兜底 (DashScope 不可达时自动切换)",
    )
    local_llm_force: bool = Field(
        default=False,
        description="强制使用本地 LLM (跳过 DashScope), 适合无 API key 或纯离线开发",
    )
    local_llm_base_url: str = Field(
        default="http://localhost:11434/v1",
        description="本地 LLM OpenAI 兼容接口 URL (Ollama 默认 11434)",
    )
    local_llm_model: str = Field(
        default="qwen2.5:7b",
        description="本地 LLM 模型名 (建议 qwen2.5:7b 或更大, 需支持 tool calling)",
    )
    local_llm_api_key: str = Field(
        default="ollama",
        description="本地 LLM API Key (Ollama 任意值即可, 一般填 'ollama')",
    )
    local_llm_probe_host: str = Field(
        default="dashscope.aliyuncs.com",
        description="探测 DashScope 是否可达的目标域名 (TCP 443)",
    )
    local_llm_probe_ttl_sec: int = Field(
        default=30,
        description="探测结果缓存秒数 (防止每次调用都探测)",
    )

    # ==================== 日志 ====================
    log_level: str = Field(default="INFO", description="日志级别")
    log_dir: str = Field(default="logs", description="日志目录")
    log_retention_days: int = Field(default=14, description="日志保留天数")

    # ==================== 计算属性 ====================
    @property
    def mcp_servers(self) -> Dict[str, Dict[str, Any]]:
        """组装 MCP 服务器配置.

        将扁平字段转为 langchain-mcp-adapters 期望的嵌套字典.
        新增 MCP 服务时, 在此添加映射.
        """
        return {
            "system": {
                "transport": self.mcp_system_transport,
                "url": self.mcp_system_url,
            },
            "websearch": {
                "transport": self.mcp_websearch_transport,
                "url": self.mcp_websearch_url,
            },
            "winlog": {
                "transport": self.mcp_winlog_transport,
                "url": self.mcp_winlog_url,
            },
            "network": {
                "transport": self.mcp_network_transport,
                "url": self.mcp_network_url,
            },
            "docker": {
                "transport": self.mcp_docker_transport,
                "url": self.mcp_docker_url,
            },
        }

    # ==================== 校验 ====================
    @field_validator("dashscope_api_key")
    @classmethod
    def _validate_api_key(cls, v: str) -> str:
        if not v or v.startswith("sk-your") or v == "":
            # 不直接 raise, 启动时由 main.py 统一检查并给出友好提示
            return v
        return v

    @field_validator("log_level")
    @classmethod
    def _normalize_log_level(cls, v: str) -> str:
        return v.upper()

    def validate_runtime(self) -> None:
        """运行时校验 (启动时调用).

        与 Pydantic 字段校验不同, 这里检查的是运行所需的实际值.
        """
        if not self.dashscope_api_key or self.dashscope_api_key.startswith("sk-your"):
            raise RuntimeError(
                "DASHSCOPE_API_KEY 未配置. 请编辑 .env 文件填入真实 API key. "
                "申请地址: https://bailian.console.aliyun.com/"
            )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """获取配置单例.

    使用 lru_cache 保证整个进程只创建一次.
    便于测试时通过 get_settings.cache_clear() 重置.
    """
    return Settings()


# 全局便捷访问
settings = get_settings()
