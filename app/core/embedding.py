"""Embedding 服务.

封装 DashScope text-embedding-v4 的向量化能力.

设计要点:
  - 用 OpenAIEmbeddings 包装 (走 DashScope 兼容模式), 而非裸调 OpenAI SDK
  - 这样可以无缝接入 langchain_milvus.Milvus.from_documents 等工具
  - 单例: 整个进程只创建一次实例
  - check_embedding_ctx_length=False: DashScope 不做 token 计数, 关掉 OpenAI 包内置的检查
"""

from functools import lru_cache

from langchain_core.embeddings import Embeddings
from langchain_openai import OpenAIEmbeddings
from loguru import logger

from app.config import settings
from app.exceptions import EmbeddingError


@lru_cache(maxsize=1)
def get_embeddings() -> Embeddings:
    """获取 Embedding 实例 (单例).

    Returns:
        Embeddings: LangChain Embeddings 接口的实例

    Raises:
        EmbeddingError: 如果配置不完整无法创建
    """
    if not settings.dashscope_api_key:
        raise EmbeddingError("DASHSCOPE_API_KEY 未配置, 无法创建 Embedding 客户端")

    logger.info(
        f"创建 Embedding 客户端: model={settings.dashscope_embedding_model}, "
        f"dim={settings.dashscope_embedding_dim}"
    )

    return OpenAIEmbeddings(
        model=settings.dashscope_embedding_model,
        api_key=settings.dashscope_api_key,  # type: ignore[arg-type]
        base_url=settings.dashscope_base_url,
        dimensions=settings.dashscope_embedding_dim,
        check_embedding_ctx_length=False,  # DashScope 无 tiktoken, 关掉检查
        # DashScope text-embedding-v4 单次最多 10 个文本, 超过会 400.
        # OpenAIEmbeddings 默认 chunk_size=2048 会把所有文本一次发出去, 必须降到 10.
        chunk_size=10,
    )
