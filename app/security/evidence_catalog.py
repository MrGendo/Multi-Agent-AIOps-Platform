"""证据目录 (Evidence Catalog) — 按 告警类型 × 资产传感器 给可执行取证动作.

与 followup.py 的关系: followup 是「通用模板」(设备→操作→证据), 本模块
叠加「资产感知」— 命中资产时, 只列该资产实际覆盖的传感器能提供的证据,
有 API 的设备 (雷池) 给可直接执行的取取证方式, 没有的给精确查询语句.

设计约束: 纯增强, 不改 followup 既有输出 — service 层先渲染通用引导,
资产命中时追加「本环境可执行取证」小节.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from loguru import logger

from app.security.asset_graph import resolve_assets

# 按传感器的取证动作库 (查询语句为设备侧可复制执行的形态)
_SENSOR_EVIDENCE: Dict[str, List[str]] = {
    "waf": [
        "雷池控制台 → 攻击事件 → 按源 IP 过滤近 24h 拦截记录 (或开放 API: scripts/poll_safeline.py)",
        "雷池 → 站点监控 → 该资产的 5xx/拦截量趋势 (判断是否正在被持续攻击)",
    ],
    "hids": [
        "Wazuh → 该主机 → Security Events → auth.log 失败/成功登录序列 (成功登录是关键证据)",
        "Wazuh → FIM (syscheck) → /tmp、web 目录新增/修改文件 (webshell 落地证据)",
        "该主机执行: ps auxf | grep -E 'kdevtmpfsi|可疑进程' 与 crontab -l (持久化检查)",
    ],
    "ndr": [
        "NDR 控制台 → 该主机 → 会话记录 → 外联目的 IP/端口/流量 (C2 外联证据)",
        "NDR → DNS 查询日志 → 该主机解析的域名清单 (DGA/C2 域名比对)",
    ],
    "ids": [
        "Suricata eve.json → 按该主机过滤 alert 事件 (scripts/ship_suricata_alerts.py 幂等搬运)",
        "Suricata → http 元数据 → UA/URI 异常 (扫描器/sqlmap 指纹)",
    ],
}

# 告警类型 → 优先取证传感器排序 (引导聚焦: 先查最可能出证据的设备)
_ALERT_SENSOR_PRIORITY: Dict[str, List[str]] = {
    "brute_force": ["hids", "waf", "ids"],
    "web_attack": ["waf", "hids", "ids"],
    "malware": ["hids", "ndr", "waf"],
    "c2_traffic": ["ndr", "hids", "ids"],
    "lateral_movement": ["ndr", "hids"],
    "data_exfiltration": ["ndr", "waf"],
    "anomaly": ["hids", "ndr", "waf", "ids"],
    "phishing": ["waf", "hids"],
    "privilege_escalation": ["hids"],
}


def build_evidence_catalog(
    alert_type: str,
    alert_text: str,
    iocs: Dict[str, List[str]] | None = None,
) -> Optional[str]:
    """按资产覆盖传感器生成「本环境可执行取证」清单; 未命中资产返回 None.

    返回 markdown 小节 (供追加到取证引导后); 命中资产但无对应传感器
    动作时也返回 None (不输出空小节).
    """
    try:
        hits = resolve_assets(alert_text, iocs)
        if not hits:
            return None
        # 资产覆盖的传感器全集
        covered: List[str] = []
        for a in hits:
            for s in a.get("sensors") or []:
                if str(s) not in covered:
                    covered.append(str(s))
        if not covered:
            return None
        # 按告警类型优先级排序, 聚焦最可能出证据的传感器
        priority = _ALERT_SENSOR_PRIORITY.get((alert_type or "anomaly").lower(), covered)
        ordered = [s for s in priority if s in covered] + [s for s in covered if s not in priority]

        lines: List[str] = []
        for s in ordered:
            actions = _SENSOR_EVIDENCE.get(s) or []
            if not actions:
                continue
            lines.append(f"- **{s.upper()}** (覆盖 {', '.join(a.get('id', '?') for a in hits if s in (a.get('sensors') or []))}):")
            lines.extend(f"  - {act}" for act in actions[:3])

        if not lines:
            return None
        assets_names = ", ".join(a.get("id", "?") for a in hits)
        return (
            f"\n### 本环境可执行取证 (资产拓扑感知)\n\n"
            f"命中资产: **{assets_names}** — 以下只列该资产实际覆盖的传感器:\n\n"
            + "\n".join(lines)
            + "\n\n> 有 API 的设备 (雷池/Suricata) 可由系统自动取证; 其余按语句在设备侧执行."
        )
    except Exception as exc:
        logger.debug(f"[EvidenceCatalog] 构建失败 (fail-soft): {exc}")
        return None
