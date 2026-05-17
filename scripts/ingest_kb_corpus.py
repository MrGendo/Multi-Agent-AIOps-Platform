"""批量入库脚本: docs/ + data/kb_corpus/ -> Milvus.

用途:
  - 把 docs/ 下的 OnCall SOP 和 data/kb_corpus/ 下的开源告警语料
    切分 -> embedding -> 写入 Milvus
  - 走和线上 RAG 一致的链路: split_markdown() + get_vector_store().add_documents()
  - 失败的文件单独记录, 不影响其他文件入库

用法:
  python scripts/ingest_kb_corpus.py             # 入库
  python scripts/ingest_kb_corpus.py --dry-run   # 只切分不入库, 看会有多少 chunks
  python scripts/ingest_kb_corpus.py --reset     # 先 drop 老 collection 再入库
  python scripts/ingest_kb_corpus.py --limit 50  # 只入前 50 个文件 (调试用)

前置条件:
  - Milvus 已启动 (docker-compose up -d)
  - DASHSCOPE_API_KEY 已配置
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import List, Tuple

# 让脚本能从仓库根目录导入 app.*
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from langchain_core.documents import Document  # noqa: E402
from loguru import logger  # noqa: E402

DOCS_DIR = ROOT / "docs" / "sop"
KB_CORPUS_DIR = ROOT / "data" / "kb_corpus"
ALLOWED_DOCS = ["redis_oncall_sop.md", "mysql_oncall_sop.md", "common_alerts.md"]


def collect_files(limit: int = 0) -> List[Tuple[Path, str]]:
    """扫描所有要入库的 (文件路径, source 标识)."""
    files: List[Tuple[Path, str]] = []

    # docs/ 下指定的 SOP 文档
    for fname in ALLOWED_DOCS:
        p = DOCS_DIR / fname
        if p.exists():
            files.append((p, fname))

    # data/kb_corpus/ 下递归所有 .md
    if KB_CORPUS_DIR.exists():
        for p in sorted(KB_CORPUS_DIR.rglob("*.md")):
            rel = p.relative_to(KB_CORPUS_DIR).as_posix()
            files.append((p, rel))

    if limit > 0:
        files = files[:limit]
    return files


def split_all(files: List[Tuple[Path, str]]) -> List[Document]:
    """把所有文件切成 Document chunks."""
    from app.utils.splitter import split_markdown

    all_chunks: List[Document] = []
    failed = 0
    for fpath, source in files:
        try:
            content = fpath.read_text(encoding="utf-8")
            chunks = split_markdown(content, source=source)
            all_chunks.extend(chunks)
        except Exception as e:
            failed += 1
            logger.warning(f"切分失败: {fpath} -> {e}")
    logger.info(
        f"切分完成: {len(files)} 文件 -> {len(all_chunks)} chunks (失败 {failed})"
    )
    return all_chunks


def ingest_to_milvus(chunks: List[Document], batch_size: int = 100) -> None:
    """分批写入 Milvus."""
    from app.core.vector_store import get_vector_store

    vs = get_vector_store()
    total = len(chunks)
    logger.info(f"开始入库: {total} chunks, batch_size={batch_size}")

    t0 = time.perf_counter()
    written = 0
    for i in range(0, total, batch_size):
        batch = chunks[i : i + batch_size]
        try:
            vs.add_documents(batch)
            written += len(batch)
            elapsed = time.perf_counter() - t0
            rate = written / max(elapsed, 0.01)
            eta = (total - written) / max(rate, 0.01)
            logger.info(
                f"  进度 {written}/{total} ({100*written/total:.1f}%), "
                f"速率 {rate:.1f} chunk/s, 剩余 {eta:.0f}s"
            )
        except Exception as e:
            logger.error(f"  batch [{i}:{i+len(batch)}] 失败: {e}")

    elapsed = time.perf_counter() - t0
    logger.info(f"入库完成: {written}/{total}, 总耗时 {elapsed:.1f}s")


def reset_collection() -> None:
    """drop 旧的 collection (慎用)."""
    from pymilvus import MilvusClient

    from app.config import settings

    uri = f"http://{settings.milvus_host}:{settings.milvus_port}"
    client = MilvusClient(uri=uri)
    if client.has_collection(settings.milvus_collection):
        client.drop_collection(settings.milvus_collection)
        logger.info(f"已 drop collection: {settings.milvus_collection}")
    else:
        logger.info(f"collection 不存在, 跳过 drop: {settings.milvus_collection}")
    # 清掉单例缓存, 让下次 get_vector_store 重建
    from app.core.vector_store import get_vector_store

    get_vector_store.cache_clear()


def main() -> None:
    parser = argparse.ArgumentParser(description="批量入库 docs/ + kb_corpus/ -> Milvus")
    parser.add_argument("--dry-run", action="store_true", help="只切分不入库")
    parser.add_argument("--reset", action="store_true", help="先 drop 老 collection")
    parser.add_argument("--limit", type=int, default=0, help="只入前 N 个文件 (0=全部)")
    parser.add_argument("--batch", type=int, default=100, help="每批入库 chunk 数")
    args = parser.parse_args()

    # 加载 .env (拿 DASHSCOPE_API_KEY / MILVUS_HOST 等)
    try:
        from dotenv import load_dotenv

        load_dotenv(ROOT / ".env")
    except ImportError:
        pass

    files = collect_files(limit=args.limit)
    logger.info(f"扫描到 {len(files)} 个 .md 文件")
    if not files:
        logger.error("没有找到任何文件, 请确认 docs/ 和 data/kb_corpus/ 下有 .md")
        sys.exit(1)

    chunks = split_all(files)
    if not chunks:
        logger.error("切分后 0 个 chunk, 退出")
        sys.exit(1)

    avg_len = sum(len(c.page_content) for c in chunks) / len(chunks)
    logger.info(
        f"切分统计: {len(chunks)} chunks, 平均 {avg_len:.0f} 字, "
        f"预计入库耗时 {len(chunks)/30:.0f}-{len(chunks)/15:.0f}s"
    )

    if args.dry_run:
        logger.info("dry-run 模式, 不入库. 示例 chunk:")
        for c in chunks[:3]:
            logger.info(f"  source={c.metadata.get('source')}")
            logger.info(f"  chapter={c.metadata.get('chapter')}")
            logger.info(f"  content[:120]={c.page_content[:120]!r}")
            logger.info("  ---")
        return

    if args.reset:
        reset_collection()

    ingest_to_milvus(chunks, batch_size=args.batch)


if __name__ == "__main__":
    main()
