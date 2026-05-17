"""知识库检索: 走 advanced_search (Vector → [Hybrid] → [Rerank]) 拼成 LLM 上下文."""

from typing import Any

from app.core.vector_store import advanced_search

# 单个片段截断上限. 800 字足以承载一个 SOP 章节要点; 超长部分让 LLM 从其它片段补.
CHUNK_CHAR_LIMIT = 800


async def build_context(
    question: str, top_k: int
) -> tuple[str, int, list[str], list[dict[str, Any]]]:
    """检索知识库, 拼接成 context 字符串.

    Returns:
        (context_text, hit_count, sources, hits_meta)
        hits_meta: [{"source", "chapter", "preview", "score"}, ...]  供前端展开显示
    """
    docs = await advanced_search(question, k=top_k)
    if not docs:
        return "(知识库未命中相关内容)", 0, [], []

    chunks: list[str] = []
    sources: list[str] = []
    hits_meta: list[dict[str, Any]] = []
    for i, doc in enumerate(docs, 1):
        meta = doc.metadata or {}
        source = meta.get("source") or "未知"
        sources.append(str(source))
        chapter = meta.get("chapter") or ""
        header = f"## 来源 {i} | {source}"
        if chapter:
            header += f" | 章节: {chapter}"
        raw_text = doc.page_content.strip()
        truncated = raw_text[:CHUNK_CHAR_LIMIT]
        if len(raw_text) > CHUNK_CHAR_LIMIT:
            truncated += "... (已截断)"
        # rerank 分数仅用于日志, 不暴露给 LLM (避免干扰回答); 但前端 progress 卡片可以展开看到
        chunks.append(f"{header}\n{truncated}")
        score = meta.get("score") or meta.get("rerank_score") or meta.get("distance")
        try:
            score_val = round(float(score), 4) if score is not None else None
        except Exception:
            score_val = None
        preview = raw_text.replace("\n", " ")
        hits_meta.append(
            {
                "source": str(source),
                "chapter": str(chapter) if chapter else "",
                "preview": preview[:240] + ("..." if len(preview) > 240 else ""),
                "score": score_val,
            }
        )

    return "\n\n".join(chunks), len(docs), sources, hits_meta
