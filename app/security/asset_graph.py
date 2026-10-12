"""资产与传感器拓扑 (Asset Graph) — 领域 agent 的环境感知层.

通用智能体的知识来自公网训练数据; 本模块描述的是「你的网络」:
什么资产、什么角色、哪些传感器罩着它、同网段还有谁. 告警进来自动
解析资产 → Analyst 上下文注入环境感知块 (爆炸半径/覆盖传感器/角色).

设计约束 (不影响现有功能):
- 纯只读旁路: 挂在 analyst 上下文构建处, 无资产文件/无命中 → 返回空串,
  原有研判行为零变化
- fail-soft: 任何异常返回空, 不阻塞研判
- data/assets.yaml 由部署者维护 (拓扑是部署侧知识, 不是代码)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

_ASSET_FILE = Path(__file__).resolve().parents[2] / "data" / "assets.yaml"

_cache: Optional[Dict[str, Any]] = None
_cache_mtime: float = 0.0


def _load_topology() -> Dict[str, Any]:
    """加载拓扑 (按 mtime 缓存, 文件更新自动重载; 损坏返回空结构)."""
    global _cache, _cache_mtime
    try:
        if not _ASSET_FILE.exists():
            return {"assets": [], "sensors": {}}
        mtime = _ASSET_FILE.stat().st_mtime
        if _cache is not None and mtime == _cache_mtime:
            return _cache
        import yaml

        data = yaml.safe_load(_ASSET_FILE.read_text(encoding="utf-8")) or {}
        _cache = {"assets": data.get("assets") or [], "sensors": data.get("sensors") or {}}
        _cache_mtime = mtime
        return _cache
    except Exception as exc:
        logger.debug(f"[AssetGraph] 拓扑加载失败 (fail-soft): {exc}")
        return {"assets": [], "sensors": {}}


def resolve_assets(text: str, iocs: Dict[str, List[str]] | None = None) -> List[Dict[str, Any]]:
    """从告警文本与 IOC 解析涉及的资产 (主机名/IP 命中), 返回资产条目列表."""
    topo = _load_topology()
    text = text or ""
    ips = set((iocs or {}).get("ips") or [])
    hits: List[Dict[str, Any]] = []
    for a in topo["assets"]:
        aid = str(a.get("id", ""))
        a_ips = [str(x) for x in (a.get("ips") or [])]
        if aid and aid in text:
            hits.append(a)
            continue
        if any(ip in ips or ip in text for ip in a_ips):
            hits.append(a)
    return hits


def build_asset_context(text: str, iocs: Dict[str, List[str]] | None = None) -> str:
    """构建 Analyst 环境感知上下文块; 无命中返回空串 (零影响).

    内容: 资产角色 (prod/PCI/DMZ/测试) + 覆盖传感器 (证据去哪取) +
    同网段资产 (横向移动评估) + 服务清单 (爆炸半径).
    """
    try:
        hits = resolve_assets(text, iocs)
        if not hits:
            return ""
        topo = _load_topology()
        by_segment: Dict[str, List[str]] = {}
        for a in topo["assets"]:
            by_segment.setdefault(str(a.get("segment", "")), []).append(str(a.get("id")))

        lines: List[str] = []
        for a in hits:
            tags = "·".join(str(t) for t in (a.get("tags") or [])) or "未标记"
            services = ", ".join(str(s) for s in (a.get("services") or [])) or "未知"
            sensors = ", ".join(str(s) for s in (a.get("sensors") or [])) or "无"
            seg = str(a.get("segment", ""))
            peers = [p for p in by_segment.get(seg, []) if p != a.get("id")]
            peer_txt = f", 同网段: {', '.join(peers[:6])}" if peers else ""
            lines.append(
                f"- {a.get('id')} [{tags}] 服务: {services}; 覆盖传感器: {sensors}{peer_txt}"
            )

        # PCI 资产命中 → 显著升级提示 (合规事件通报义务)
        pci_hit = any("pci" in (a.get("tags") or []) for a in hits)
        pci_note = (
            "\n注意: 涉及 PCI 范围资产 — 若确认为入侵, 触发合规事件通报流程, "
            "响应等级建议上调一档." if pci_hit else ""
        )
        return (
            "**ASSET CONTEXT (来自本地资产拓扑, 环境事实):**\n"
            + "\n".join(lines)
            + "\n用途: 评估爆炸半径 (服务/同网段) 与取证路径 (覆盖传感器即证据来源); "
            "角色标签影响响应等级 (prod/pci 高于 test)."
            + pci_note
        )
    except Exception as exc:
        logger.debug(f"[AssetGraph] 环境上下文构建失败 (fail-soft): {exc}")
        return ""


def sensor_coverage_gap(alert_text: str, iocs: Dict[str, List[str]] | None = None) -> List[str]:
    """覆盖缺口: 命中资产但某传感器 30 分钟无任何事件 → 该传感器可能断流.

    供覆盖自监用 (meta-alert); 无资产文件时返回空列表.
    注意: 本函数只做「拓扑 vs 已见传感器」静态比对, 时效判断由调用方
    (基于 alert_history 的最近事件) 完成.
    """
    try:
        hits = resolve_assets(alert_text, iocs)
        if not hits:
            return []
        seen_sources = set()
        try:
            hist_file = Path(__file__).resolve().parents[2] / "data" / "alert_history.jsonl"
            if hist_file.exists():
                import json

                for line in hist_file.read_text(encoding="utf-8").splitlines()[-200:]:
                    try:
                        rec = json.loads(line)
                        src = (rec.get("alert") or {}).get("source") or ""
                        if src:
                            seen_sources.add(src)
                    except Exception:
                        continue
        except Exception:
            pass
        gaps: List[str] = []
        for a in hits:
            for s in a.get("sensors") or []:
                if str(s) not in seen_sources:
                    gaps.append(f"{a.get('id')}: 传感器 {s} 无近期事件 (可能断流/未接入)")
        return gaps
    except Exception as exc:
        logger.debug(f"[AssetGraph] 覆盖检查失败 (fail-soft): {exc}")
        return []
