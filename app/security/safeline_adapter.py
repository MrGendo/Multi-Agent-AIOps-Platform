"""长亭雷池 (SafeLine) WAF 告警适配器.

两种接入形态:
  1. webhook: 雷池社区版无原生 webhook, 但转发层 (如自定义脚本/中间件)
     可把事件 JSON 直接 POST 到 /webhook/security, 本模块做结构识别归一
  2. 开放 API 拉取: GET /api/open/events (X-Api-Token 认证),
     scripts/poll_safeline.py 定时拉取并转发

格式来源: chaitin/SafeLine mcp_server/internal/api (官方仓库 Go 结构体):
  Event: id/ip/protocol/host/dst_port/updated_at/start_at/end_at/
         deny_count/pass_count/finished/country/province/city
  Response: {code, message, data: {nodes: [...], total}}
"""

from __future__ import annotations

from typing import Any, Dict, Optional


def is_safeline_event(payload: Dict[str, Any]) -> bool:
    """识别雷池事件结构: 聚合事件特征字段组合."""
    if not isinstance(payload, dict):
        return False
    # 完整事件: ip + host + deny_count/pass_count 计数字段是雷池聚合事件的指纹
    if "ip" in payload and "host" in payload and (
        "deny_count" in payload or "pass_count" in payload
    ):
        return True
    # api 响应包装: {code, data: {nodes: [...]}}
    data = payload.get("data")
    if (
        isinstance(data, dict)
        and isinstance(data.get("nodes"), list)
        and "code" in payload
    ):
        return True
    return False


def _payload_cls():
    from app.api.v1.webhook import SecurityAlertPayload

    return SecurityAlertPayload


def _classify_attack(host: str, deny_count: int, pass_count: int) -> tuple[str, str]:
    """粗分类攻击类型 (聚合事件无 attack_type 字段, 按 deny/pass 比例)."""
    total = deny_count + pass_count
    if deny_count > 0 and total > 0 and deny_count / total >= 0.9:
        return "web_attack", "高拦截率 — 明确的 Web 攻击行为被 WAF 阻断"
    if deny_count > 100:
        return "brute_force", "高频拦截 — CC/爆破类高频攻击特征"
    if deny_count > 0:
        return "web_attack", "存在拦截 — 疑似 Web 攻击探测"
    return "anomaly", "全部放行 — 异常流量特征待研判"


def adapt_safeline_event(ev: Dict[str, Any]) -> Any:
    """单条雷池聚合事件 -> 统一 payload."""
    ip = str(ev.get("ip") or "")
    host = str(ev.get("host") or "")
    dst_port = ev.get("dst_port") or 0
    deny = int(ev.get("deny_count") or 0)
    passed = int(ev.get("pass_count") or 0)
    start = ev.get("start_at") or 0
    end = ev.get("end_at") or 0
    geo = "/".join(
        p for p in (ev.get("country"), ev.get("province"), ev.get("city")) if p
    )
    alert_type, type_reason = _classify_attack(host, deny, passed)

    # deny 主导 -> 至少 HIGH; 全放行待研判 -> MEDIUM
    severity = "HIGH" if deny >= max(10, passed) else ("MEDIUM" if deny else "LOW")

    window = ""
    if start and end:
        window = f"时间窗 {start}-{end}"

    desc_lines = [
        f"雷池 WAF 聚合攻击事件 (host={host or '未知'}:{dst_port})",
        f"拦截 {deny} 次 / 放行 {passed} 次 {window}",
        f"分类依据: {type_reason}",
        f"攻击方向: {ip} -> {host}:{dst_port}",
    ]
    if geo:
        desc_lines.append(f"源 IP 归属地: {geo}")
    if ev.get("finished"):
        desc_lines.append("事件状态: 已结束")

    return _payload_cls()(
        source="safeline",
        severity=severity,
        rule=f"[SafeLine] {alert_type} @ {host or ip}",
        description="\n".join(desc_lines),
        src_ip=ip,
        dst_ip="",
        agent=host,
        fingerprint=f"safeline-{ev.get('id') or f'{ip}-{host}-{start}'}",
    )


def adapt_safeline_payload(payload: Dict[str, Any]) -> Optional[Any]:
    """识别 + 归一: 接收裸事件或 API 响应包装, 返回 payload 或 None.

    API 响应包装 ({code, data:{nodes}}) 时只取 nodes[0] (webhook 单条语义);
    多条拉取请用 scripts/poll_safeline.py 逐条转发.
    """
    if not isinstance(payload, dict) or not is_safeline_event(payload):
        return None
    data = payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("nodes"), list):
        nodes = [n for n in data["nodes"] if isinstance(n, dict)]
        if not nodes:
            return None
        return adapt_safeline_event(nodes[0])
    return adapt_safeline_event(payload)
