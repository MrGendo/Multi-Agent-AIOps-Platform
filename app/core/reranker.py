"""Reranker 封装 (DashScope gte-rerank-v2).

为什么要加 Reranker
======================
向量检索 (bi-encoder) 把 query 和 doc 分别编码成向量后算 cosine, 这是一次"粗排":
  - 优点: 预先算好 doc 向量, 查询时只算 query 向量 + 一次 ANN 搜索, 延迟低
  - 局限: query 和 doc 从未在同一个模型上下文中交互过, 对细粒度语义差异不敏感
         (比如 "Redis 内存占用高" vs "Redis 内存泄漏排查", 向量很接近但问的是不同事)

Reranker (cross-encoder) 把 (query, doc) 作为一对一起送进模型, 能捕捉精细的语义关联:
  - 优点: 准确度显著高于 bi-encoder (Anthropic 实测 top-20 失败率从 3.7% 降到 1.9%)
  - 局限: 每对都要跑一次模型, 无法提前算好 → 只能用在"粗排后重排少量候选"这一步

典型流水线
======================
  用户 query ─▶ (Hybrid: BM25 ∪ Vector) 取 top-20 ─▶ Rerank ─▶ 取 top-3 ─▶ LLM

为什么选 DashScope gte-rerank-v2 (而不是本地 BGE / Cohere)
======================
  - 复用项目已有的 DashScope API Key, 不引入新依赖、新凭证
  - 不需要本地模型权重 (BGE-reranker 模型 500MB+, 冷启动慢)
  - gte-rerank-v2 是通义实验室多语言模型, 对中英混合 SOP 文档友好
  - 局限: 需联网访问 DashScope; 网络故障/超时会自动降级 (见 rerank_docs)

降级策略
======================
任何异常都返回原始 docs 的前 top_n 项, 不阻断业务:
  - API Key 缺失       → 直接降级
  - 网络超时           → 降级
  - 响应格式异常       → 降级
  - docs 为空          → 直接返回空
"""

from __future__ import annotations

from typing import List, Optional

import httpx
from langchain_core.documents import Document
from loguru import logger

from app.config import settings

# DashScope Rerank HTTP 接口
# 文档: https://help.aliyun.com/zh/model-studio/developer-reference/text-rerank-api
_RERANK_ENDPOINT = (
    "https://dashscope.aliyuncs.com/api/v1/services/rerank/text-rerank/text-rerank"
)


async def rerank_docs(
    query: str,
    docs: List[Document],
    *,
    top_n: Optional[int] = None,
    model: Optional[str] = None,
    timeout: Optional[float] = None,
) -> List[Document]:
    """对候选文档做 Rerank, 返回按相关性降序排列的 top_n 个.

    Args:
        query:   用户原始问题
        docs:    粗排候选 (通常 10-30 个)
        top_n:   返回多少个 (None = settings.rag_top_k)
        model:   rerank 模型名 (None = settings.rag_rerank_model)
        timeout: 单次调用超时秒 (None = settings.rag_rerank_timeout_sec)

    Returns:
        List[Document]: 重排后的 top_n 文档 (原 Document 对象, 附加
        doc.metadata["rerank_score"] 表示 reranker 给出的分数; 发生降级时
        无该字段).

    保证:
        永不抛异常. 任何故障都降级为 docs[:top_n].
    """
    top_n = top_n if top_n is not None else settings.rag_top_k
    model = model or settings.rag_rerank_model
    timeout = timeout if timeout is not None else settings.rag_rerank_timeout_sec

    if not docs:
        return []
    if top_n <= 0:
        return []

    # 1) 前置校验: 没有 API key 直接降级, 避免无意义的 401
    api_key = settings.dashscope_api_key
    if not api_key or api_key.startswith("sk-your"):
        logger.warning("[rerank] 无 API key, 降级到粗排前 top_n")
        return docs[:top_n]

    # 2) 构造请求
    # DashScope 要求 documents 是 str 列表; 我们保留下标映射, 重排后用下标取回 Document
    doc_texts = [d.page_content for d in docs]

    payload = {
        "model": model,
        "input": {
            "query": query,
            "documents": doc_texts,
        },
        "parameters": {
            "top_n": min(top_n, len(docs)),
            "return_documents": False,  # 不需要回传原文, 省带宽
        },
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    # 3) 调用
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(_RERANK_ENDPOINT, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
    except httpx.TimeoutException:
        logger.warning(f"[rerank] 超时 ({timeout}s), 降级到粗排前 top_n")
        return docs[:top_n]
    except httpx.HTTPStatusError as e:
        logger.warning(f"[rerank] HTTP {e.response.status_code}: {e.response.text[:200]}")
        return docs[:top_n]
    except Exception as e:
        logger.warning(f"[rerank] 调用失败, 降级: {type(e).__name__}: {e}")
        return docs[:top_n]

    # 4) 解析响应
    # DashScope 返回形如 {"output": {"results": [{"index": 2, "relevance_score": 0.87}, ...]}}
    try:
        results = data.get("output", {}).get("results") or []
        if not results:
            logger.warning(f"[rerank] 响应 results 为空, 降级. raw={str(data)[:200]}")
            return docs[:top_n]

        reranked: List[Document] = []
        for item in results:
            idx = item.get("index")
            score = item.get("relevance_score")
            if idx is None or not (0 <= idx < len(docs)):
                continue
            doc = docs[idx]
            # 写分数到 metadata (不修改原对象, 复制一个)
            new_meta = dict(doc.metadata or {})
            if score is not None:
                new_meta["rerank_score"] = float(score)
            reranked.append(
                Document(page_content=doc.page_content, metadata=new_meta)
            )
            if len(reranked) >= top_n:
                break

        if not reranked:
            return docs[:top_n]

        logger.info(
            f"[rerank] ok: query={query[:40]!r} "
            f"candidates={len(docs)} -> top_n={len(reranked)} "
            f"top1_score={reranked[0].metadata.get('rerank_score'):.3f}"
        )
        return reranked

    except Exception as e:
        logger.warning(f"[rerank] 解析响应失败, 降级: {type(e).__name__}: {e}")
        return docs[:top_n]
