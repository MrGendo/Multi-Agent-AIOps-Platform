"""文档分块器.

两遍切分:
  1. 按 Markdown 标题切 (MarkdownHeaderTextSplitter)
     → 保留章节结构到 metadata, 便于 RAG 引用时显示来源章节
  2. 大块再按字符数切 (RecursiveCharacterTextSplitter)
     → 防止单个章节过大, 超出 LLM 上下文窗口或检索时召回不准

设计要点:
  - 写入 metadata: source (文件名), chapter (从 H1/H2/H3 拼接)
  - 大小可配置: settings.rag_chunk_size / rag_chunk_overlap
"""

from typing import List

from langchain_core.documents import Document
from langchain_text_splitters import (
    MarkdownHeaderTextSplitter,
    RecursiveCharacterTextSplitter,
)
from loguru import logger

from app.config import settings

# Markdown 标题层级 → metadata 字段名
_HEADERS_TO_SPLIT_ON = [
    ("#", "h1"),
    ("##", "h2"),
    ("###", "h3"),
]


def split_markdown(content: str, source: str) -> List[Document]:
    """把 Markdown 文档切成多个 Document chunks.

    Args:
        content: Markdown 全文
        source:  来源标识 (通常是文件名), 写入 metadata

    Returns:
        List[Document]: 每个 chunk 都带 metadata = {source, chapter, h1, h2, h3, chunk_index}
    """
    if not content.strip():
        logger.warning(f"split_markdown: 空内容 source={source}")
        return []

    # ---------- 第一遍: 按标题分 ----------
    md_splitter = MarkdownHeaderTextSplitter(
        headers_to_split_on=_HEADERS_TO_SPLIT_ON,
        strip_headers=False,  # 保留标题, RAG 引用更直观
    )
    header_chunks = md_splitter.split_text(content)

    if not header_chunks:
        # 文档没有标题, 退化为整篇当一个块
        header_chunks = [Document(page_content=content, metadata={})]

    # ---------- 第二遍: 大块再切 ----------
    char_splitter = RecursiveCharacterTextSplitter(
        chunk_size=settings.rag_chunk_size,
        chunk_overlap=settings.rag_chunk_overlap,
        separators=["\n\n", "\n", "。", "!", "?", "；", ";", " ", ""],
    )

    final_chunks: List[Document] = []
    for hc in header_chunks:
        sub_docs = char_splitter.split_documents([hc])
        final_chunks.extend(sub_docs)

    # ---------- 给每个 chunk 注入元数据 + 章节前缀 ----------
    # 章节前缀: 把 [h1 / h2 / h3] 拼到 chunk 正文最前面, 让章节路径参与 embedding.
    # 离线评估 (954 文档 / 4080 chunks) 显示: R@1 从 83.33% 提升到 91.67% (+10%),
    # MRR 从 0.882 到 0.938. 主要解决跨服务关键词撞车的召回错位问题.
    for idx, doc in enumerate(final_chunks):
        meta = doc.metadata or {}
        # 拼章节路径: "第 1 章 / 1.1 节 / 1.1.1 小节"
        chapter_parts = [meta.get("h1"), meta.get("h2"), meta.get("h3")]
        chapter = " / ".join(p for p in chapter_parts if p)
        doc.metadata = {
            **meta,
            "source": source,
            "chapter": chapter,
            "chunk_index": idx,
        }
        # 注入章节前缀到正文, 参与 embedding (实测大规模下 +10% R@1)
        if chapter:
            doc.page_content = f"[{chapter}]\n{doc.page_content}"

    logger.info(
        f"[splitter] {source}: header_chunks={len(header_chunks)}, "
        f"final_chunks={len(final_chunks)}"
    )
    return final_chunks
