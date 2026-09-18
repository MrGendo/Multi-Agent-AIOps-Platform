"""CEF (Common Event Format) 通用安全事件适配器.

CEF 是 ArcSight 定义的事实标准, 国内外大量 NDR/EDR/SIEM/防火墙支持以
CEF 格式导出事件 (syslog 或 HTTP). 一个适配器覆盖一类设备.

格式:
  CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
  Extension 是 key=value 空格分隔, 值含空格时用 \\ 转义或反引号包裹.

示例:
  CEF:0|Security|threat|1.0|100|Suspicious SQL Injection|8|src=45.33.32.156 dst=10.0.0.8 request=/search?q=1' UNION SELECT outcome=blocked

severity 映射: CEF 0-10 -> LOW(0-3) / MEDIUM(4-6) / HIGH(7-8) / CRITICAL(9-10)
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

# CEF 头: CEF:version|vendor|product|version|sigid|name|severity|extension
_CEF_RE = re.compile(
    r"^CEF:(?P<ver>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|"
    r"(?P<dver>[^|]*)\|(?P<sigid>[^|]*)\|(?P<name>[^|]*)\|(?P<sev>[^|]*)\|(?P<ext>.*)$",
    re.DOTALL,
)

# extension 手写解析 (正则 alternation 的捕获组计数易错, 逐字符更稳):
# key=value, 值可以是 "..." / `...` / 反斜杠转义空格的裸词
def _parse_extension(ext: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    i, n = 0, len(ext)
    while i < n:
        # 跳过空白
        while i < n and ext[i] == " ":
            i += 1
        # key
        key_start = i
        while i < n and ext[i] not in "= ":
            i += 1
        key = ext[key_start:i]
        if not key or i >= n or ext[i] != "=":
            # 无 = 的孤词, 跳过
            if i < n and ext[i] == " ":
                continue
            break
        i += 1  # 跳过 =
        # value
        if i < n and ext[i] == '"':
            j = ext.find('"', i + 1)
            if j < 0:
                j = n
            val = ext[i + 1 : j]
            i = j + 1 if j < n else n
        elif i < n and ext[i] == "`":
            j = ext.find("`", i + 1)
            if j < 0:
                j = n
            val = ext[i + 1 : j]
            i = j + 1 if j < n else n
        else:
            chars = []
            while i < n:
                c = ext[i]
                if c == "\\" and i + 1 < n and ext[i + 1] == " ":
                    chars.append(" ")
                    i += 2
                elif c == " ":
                    break
                else:
                    chars.append(c)
                    i += 1
            val = "".join(chars)
        if key:
            result[key] = val
    return result


def _cef_severity_to_ours(sev: Any) -> str:
    try:
        s = int(float(str(sev).strip() or "0"))
    except (TypeError, ValueError):
        return "MEDIUM"
    if s >= 9:
        return "CRITICAL"
    if s >= 7:
        return "HIGH"
    if s >= 4:
        return "MEDIUM"
    return "LOW"


def parse_cef(line: str) -> Optional[Dict[str, Any]]:
    """解析单条 CEF 为 {header fields..., extension dict} 结构; 非 CEF 返回 None."""
    if not line:
        return None
    line = line.strip()
    # syslog 前缀 (优先级/时间戳/主机名) 剥掉
    if "CEF:" in line and not line.startswith("CEF:"):
        line = line[line.index("CEF:"):]
    m = _CEF_RE.match(line)
    if not m:
        return None
    ext = _parse_extension(m.group("ext") or "")
    return {
        "version": m.group("ver"),
        "vendor": m.group("vendor"),
        "product": m.group("product"),
        "device_version": m.group("dver"),
        "signature_id": m.group("sigid"),
        "name": m.group("name"),
        "severity": m.group("sev"),
        "extension": ext,
    }


def is_cef_text(text: str) -> bool:
    """粗判文本是否 CEF 格式."""
    return bool(text) and "CEF:" in text[:600] and "|" in text


def _payload_cls():
    from app.api.v1.webhook import SecurityAlertPayload

    return SecurityAlertPayload


def adapt_cef_text(text: str) -> Optional[Any]:
    """CEF 文本 (单条或多行取第一条) -> 统一 payload; 非 CEF 返回 None."""
    if not is_cef_text(text):
        return None
    # 多行取第一条有效 CEF
    parsed = None
    for line in text.splitlines():
        if "CEF:" in line:
            parsed = parse_cef(line)
            if parsed:
                break
    if not parsed:
        return None

    ext = parsed["extension"] or {}
    src_ip = ext.get("src") or ext.get("srcIp") or ext.get("sourceAddress") or ""
    dst_ip = ext.get("dst") or ext.get("dstIp") or ext.get("destinationAddress") or ""
    host = ext.get("dhost") or ext.get("destinationHostName") or ext.get("shost") or ""
    request = ext.get("request") or ext.get("requestURL") or ""
    outcome = ext.get("outcome") or ext.get("action") or ""
    msg = ext.get("msg") or ""
    user = ext.get("duser") or ext.get("suser") or ""

    desc_lines = [
        f"CEF 事件: {parsed['name'] or '未命名'}",
        f"设备: {parsed['vendor']} {parsed['product']} (sig={parsed['signature_id'] or '?'})",
        f"CEF severity: {parsed['severity']} -> { _cef_severity_to_ours(parsed['severity'])}",
    ]
    if msg:
        desc_lines.append(f"描述: {msg[:500]}")
    if request:
        desc_lines.append(f"请求: {request[:300]}")
    if outcome:
        desc_lines.append(f"处置: {outcome}")
    if user:
        desc_lines.append(f"账号: {user}")

    return _payload_cls()(
        source=f"cef:{parsed['vendor'] or 'generic'}:{parsed['product'] or 'device'}",
        severity=_cef_severity_to_ours(parsed["severity"]),
        rule=f"[{parsed['signature_id'] or 'sig'}] {parsed['name'] or 'CEF event'}",
        description="\n".join(desc_lines),
        src_ip=src_ip,
        dst_ip=dst_ip,
        agent=host,
        fingerprint=f"cef-{parsed['signature_id'] or 'x'}-{src_ip}-{(request or msg)[:40]}",
    )
