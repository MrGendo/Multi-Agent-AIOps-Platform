"""主流安全设备告警格式适配器 (Wazuh / Suricata EVE / Falco).

自动识别原生 payload 结构, 归一化为统一 SecurityAlertPayload:
  - Wazuh: {"alert": {...}} 或裸 alert dict (rule/agent/data/full_log)
  - Suricata EVE: {"event_type": "alert", "alert": {...}, "src_ip", ...}
  - Falco: {"output", "rule", "priority", "time"}
  - 其余: 返回 None (走通用 schema)

severity 映射:
  - Wazuh level 0-15: <=3 LOW / 4-7 MEDIUM / 8-11 HIGH / >=12 CRITICAL
  - Suricata severity 1-3 (1 最高): 1 CRITICAL / 2 HIGH / 3 MEDIUM
  - Falco priority: Emergency/Alert/Critical→CRITICAL, Error→HIGH,
    Warning/Notice→MEDIUM, Informational/Debug→LOW
"""

from __future__ import annotations

from typing import Any, Dict, Optional


def _payload_cls():
    """惰性取 SecurityAlertPayload (避免 device_adapters → webhook → security 循环 import)."""
    from app.api.v1.webhook import SecurityAlertPayload

    return SecurityAlertPayload


def _wazuh_severity(level: Any) -> str:
    try:
        lv = int(level)
    except (TypeError, ValueError):
        return "MEDIUM"
    if lv >= 12:
        return "CRITICAL"
    if lv >= 8:
        return "HIGH"
    if lv >= 4:
        return "MEDIUM"
    return "LOW"


def _suricata_severity(sev: Any) -> str:
    try:
        s = int(sev)
    except (TypeError, ValueError):
        return "MEDIUM"
    # EVE severity: 1=最高
    return {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM"}.get(s, "MEDIUM")


def _falco_severity(priority: str) -> str:
    p = (priority or "").lower()
    if p in ("emergency", "alert", "critical"):
        return "CRITICAL"
    if p == "error":
        return "HIGH"
    if p in ("warning", "notice"):
        return "MEDIUM"
    return "LOW"


def _adapt_wazuh(alert: Dict[str, Any]) -> "Any":
    """Wazuh alert dict -> 统一 payload."""
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    full_log = alert.get("full_log") or ""

    parts = []
    if rule.get("description"):
        parts.append(str(rule["description"]))
    if rule.get("groups"):
        groups = rule["groups"]
        parts.append(f"rule groups: {', '.join(groups) if isinstance(groups, list) else groups}")
    if full_log:
        parts.append(f"原始日志: {str(full_log)[:600]}")
    # data 里的附加字段 (srcuser/dstuser/file 等对研判有价值)
    for key in ("srcuser", "dstuser", "dstip", "srcport", "dstport", "file", "command", "url"):
        if data.get(key):
            parts.append(f"{key}: {data[key]}")

    return _payload_cls()(
        source="wazuh",
        severity=_wazuh_severity(rule.get("level", 4)),
        rule=f"[{rule.get('id', '?')}] {rule.get('description', 'Wazuh rule')}",
        description="\n".join(parts),
        src_ip=str(data.get("srcip") or "") or "",
        dst_ip=str(data.get("dstip") or "") or "",
        agent=str(agent.get("name") or "") or "",
        fingerprint=str(rule.get("id") or "") + "@" + str(agent.get("name") or ""),
    )


def _adapt_suricata(ev: Dict[str, Any]) -> "Any":
    """Suricata EVE alert 事件 -> 统一 payload."""
    alert = ev.get("alert") or {}
    parts = []
    if alert.get("signature"):
        parts.append(str(alert["signature"]))
    if alert.get("category"):
        parts.append(f"category: {alert['category']}")
    # http/dns/file 元数据增强 IOC 提取
    http = ev.get("http") or {}
    if http.get("hostname") or http.get("url"):
        parts.append(f"http: {http.get('hostname', '')}{http.get('url', '')} "
                     f"method={http.get('http_method', '')} ua={http.get('http_user_agent', '')}")
    dns = ev.get("dns") or {}
    rr = dns.get("rrname")
    if rr:
        parts.append(f"dns query: {rr}")
    if ev.get("flow_id"):
        parts.append(f"flow_id: {ev['flow_id']}")

    return _payload_cls()(
        source="suricata",
        severity=_suricata_severity(alert.get("severity", 3)),
        rule=str(alert.get("signature", "Suricata alert")),
        description="\n".join(parts),
        src_ip=str(ev.get("src_ip") or ""),
        dst_ip=str(ev.get("dest_ip") or ""),
        agent="",
        fingerprint=f"suricata-{ev.get('flow_id', '')}-{alert.get('signature_id', '')}",
    )


def _adapt_falco(ev: Dict[str, Any]) -> "Any":
    """Falco webhook 输出 -> 统一 payload."""
    output = str(ev.get("output") or "")
    fields = ev.get("output_fields") or {}
    src_ip = str(fields.get("fd.sip") or fields.get("connection.sip") or "") or ""
    return _payload_cls()(
        source="falco",
        severity=_falco_severity(str(ev.get("priority") or "")),
        rule=str(ev.get("rule") or "Falco rule"),
        description=output[:800],
        src_ip=src_ip,
        dst_ip="",
        agent=str(fields.get("host.name") or "") or "",
        fingerprint=f"falco-{ev.get('rule', '')}",
    )


def detect_and_normalize(payload: Dict[str, Any]) -> Optional[Any]:
    """识别设备格式并归一化; 未识别返回 None (调用方走通用 schema).

    支持: Wazuh / Suricata EVE / Falco / 长亭雷池 SafeLine / CEF 文本
    (装在 {"cef_text": "..."} 或 {"text": "CEF:..."} 包装里, syslog 转发常见).
    """
    if not isinstance(payload, dict):
        return None
    # CEF: 文本包装 (syslog 转发器/HTTP 网关把 CEF 日志行塞进 text 字段)
    raw_text = payload.get("cef_text") or payload.get("text") or ""
    if isinstance(raw_text, str) and "CEF:" in raw_text[:600]:
        from app.security.cef_adapter import adapt_cef_text

        adapted = adapt_cef_text(raw_text)
        if adapted is not None:
            return adapted
    # 长亭雷池 SafeLine (裸聚合事件 或 API 响应包装)
    from app.security.safeline_adapter import adapt_safeline_payload

    adapted = adapt_safeline_payload(payload)
    if adapted is not None:
        return adapted
    # Wazuh: 包裹 {"alert": {...}} 或裸 dict 带 rule.id + (agent|full_log|data)
    candidate = payload.get("alert") if isinstance(payload.get("alert"), dict) else None
    if candidate and isinstance(candidate.get("rule"), dict):
        return _adapt_wazuh(candidate)
    if isinstance(payload.get("rule"), dict) and (
        payload.get("agent") or payload.get("full_log") or payload.get("data")
    ):
        return _adapt_wazuh(payload)
    # Suricata EVE
    if payload.get("event_type") == "alert" and isinstance(payload.get("alert"), dict):
        return _adapt_suricata(payload)
    # Falco
    if payload.get("rule") and payload.get("output") and payload.get("priority"):
        return _adapt_falco(payload)
    return None
