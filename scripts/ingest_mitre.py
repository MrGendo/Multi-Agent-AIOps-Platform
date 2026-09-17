"""MITRE ATT&CK Enterprise 知识库入库脚本.

下载官方 STIX 数据 → 转成 Markdown 文档 (每技术一篇: 战术/描述/检测建议/
缓解措施/平台/数据源) → 切分入库 Milvus (source=mitre_attack).

用法 (无 Docker 机器: milvus-lite; 入库前必须停 uvicorn — 单进程独占锁):
    .venv/bin/python scripts/ingest_mitre.py            # 全量 697 技术
    .venv/bin/python scripts/ingest_mitre.py --dry-run  # 只转换不入库

数据源: https://github.com/mitre-attack/attack-stix-data (CC BY 4.0).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import tempfile
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.vector_store import get_vector_store  # noqa: E402
from app.utils.splitter import split_markdown  # noqa: E402

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
SOURCE = "mitre_attack"


def _clean(text: str) -> str:
    """去 STIX 内联引用标记."""
    return re.sub(r"\(Citation: [^)]+\)", "", text or "").strip()


def convert(stix: dict) -> list[dict]:
    """STIX bundle → [{tid, name, content}] 文档列表."""
    objects = stix["objects"]
    by_id = {o["id"]: o for o in objects if "id" in o}

    # mitigates 关系: coa -> technique
    mitigations: dict[str, list[str]] = {}
    for rel in objects:
        if rel.get("type") == "relationship" and rel.get("relationship_type") == "mitigates":
            src = by_id.get(rel.get("source_ref"))
            if src and rel.get("target_ref"):
                mitigations.setdefault(rel["target_ref"], []).append(src.get("name", ""))

    docs = []
    for t in objects:
        if t.get("type") != "attack-pattern" or t.get("revoked") or t.get("x_mitre_deprecated"):
            continue
        tid = url = ""
        for ref in t.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith("T"):
                tid, url = ref["external_id"], ref.get("url", "")
                break
        if not tid:
            continue

        name = t.get("name", "")
        phases = [
            p.get("phase_name", "")
            for p in t.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        coas = sorted(set(m for m in mitigations.get(t["id"], []) if m))

        lines = [f"# {tid} {name}", ""]
        if phases:
            lines += [f"## 战术\n{', '.join(phases)}", ""]
        if _clean(t.get("description", "")):
            lines += [f"## 描述\n{_clean(t['description'])}", ""]
        if _clean(t.get("x_mitre_detection", "")):
            lines += [f"## 检测建议\n{_clean(t['x_mitre_detection'])}", ""]
        if coas:
            lines += ["## 缓解措施\n" + "\n".join(f"- {c}" for c in coas[:10]), ""]
        if t.get("x_mitre_platforms"):
            lines += [f"## 平台\n{', '.join(t['x_mitre_platforms'])}", ""]
        if t.get("x_mitre_data_sources"):
            lines += [f"## 数据源\n{', '.join(t['x_mitre_data_sources'][:8])}", ""]
        if url:
            lines += [f"## 参考\n{url}", ""]
        docs.append({"tid": tid, "name": name, "content": "\n".join(lines)})
    return docs


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="只转换不入库")
    parser.add_argument("--stix", default="", help="本地 STIX json 路径 (跳过下载)")
    args = parser.parse_args()

    # 1. 获取 STIX
    if args.stix:
        stix = json.loads(Path(args.stix).read_text())
        print(f"[mitre] 使用本地 STIX: {args.stix}")
    else:
        print(f"[mitre] 下载 {STIX_URL} (~52MB)...")
        async with httpx.AsyncClient(timeout=300, follow_redirects=True) as client:
            resp = await client.get(STIX_URL)
            resp.raise_for_status()
            stix = resp.json()
        # 落盘缓存供复用
        cache = Path(tempfile.gettempdir()) / "enterprise-attack.json"
        cache.write_text(json.dumps(stix))
        print(f"[mitre] 已缓存至 {cache}")

    # 2. 转换
    docs = convert(stix)
    print(f"[mitre] 转换出 {len(docs)} 个技术文档")
    if args.dry_run:
        sample = next((d for d in docs if d["tid"] == "T1110"), docs[0])
        print(f"[mitre] dry-run 样例 {sample['tid']}:\n{sample['content'][:400]}")
        return

    # 3. 入库 (metadata 键补齐 — Milvus 缺键即 DataNotMatch, h1/h2/h3 必须显式)
    vs = get_vector_store()
    total_chunks = 0
    batch = 50
    for i in range(0, len(docs), batch):
        sub = docs[i : i + batch]
        for doc in sub:
            chunks = split_markdown(doc["content"], source=SOURCE)
            for idx, chunk in enumerate(chunks):
                meta = chunk.metadata or {}
                meta.setdefault("h1", "")
                meta.setdefault("h2", "")
                meta.setdefault("h3", "")
                meta["tid"] = doc["tid"]
                meta["tech_name"] = doc["name"]
                meta["type"] = "mitre_technique"
                chunk.metadata = meta
            vs.add_documents(chunks)
            total_chunks += len(chunks)
        print(f"[mitre] 入库进度 {min(i + batch, len(docs))}/{len(docs)} (chunks={total_chunks})")

    print(f"[mitre] 完成: {len(docs)} 技术 → {total_chunks} chunks (source={SOURCE})")


if __name__ == "__main__":
    asyncio.run(main())
