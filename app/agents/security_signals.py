"""跨域反向提示 (AIOps → SecOps handoff hint).

运维诊断报告中出现安全特征词时, 在 report 事件后追加一条
`cross_domain_hint` SSE 事件 — 只提示不自动转 (避免误判循环,
由分析师决定是否移交安全研判).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

# 安全特征词 (AIOps 诊断报告命中即提示移交安全研判)
_SECURITY_SIGNALS: List[str] = [
    "挖矿",
    "后门",
    "webshell",
    "可疑外联",
    "爆破",
    "暴力破解",
    "恶意进程",
    "反向 shell",
    "reverse shell",
    "勒索",
    "挖矿木马",
    "异常外联",
    "C2",
    "command and control",
]

_PATTERN = re.compile("|".join(re.escape(s) for s in _SECURITY_SIGNALS), re.IGNORECASE)


def scan_security_signals(report_text: str) -> Dict[str, Any] | None:
    """扫描诊断报告, 命中安全特征词时返回提示 payload (未命中返回 None).

    返回: {"matched": [命中的特征词去重], "hint": 建议文案}
    """
    if not report_text:
        return None
    matched = list(dict.fromkeys(m.group(0).lower() for m in _PATTERN.finditer(report_text)))
    if not matched:
        return None
    return {
        "matched": matched,
        "hint": (
            "诊断报告含安全特征信号, 疑似安全事件 (非单纯故障). "
            "建议移交安全研判 (SecOps) 做攻击确认与 IOC 取证."
        ),
    }
