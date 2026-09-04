"""消息内容提取的跨协议兼容助手.

背景: ChatOpenAI 的 AIMessage.content 是 str, 而 ChatAnthropic
(GLM Coding Plan 走 Anthropic 协议) 是 block 列表:
    [{"type": "thinking", "thinking": "..."}, {"type": "text", "text": "..."}]
下游代码一律通过 extract_text() 拿纯文本, 避免 'list' object has no
attribute 'replace' 这类协议差异炸裂 (2026-09-04 生产实测踩坑).
"""

from __future__ import annotations

from typing import Any


def extract_text(msg: Any) -> str:
    """从 AIMessage / 任意消息对象提取纯文本 (跨 OpenAI/Anthropic 协议).

    - str → 原样返回
    - block 列表 → 拼接 type=="text" 块 (跳过 thinking/工具块)
    - 其他 → str() 兜底
    """
    content = getattr(msg, "content", msg)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(item.get("text", ""))
            elif isinstance(item, str):
                parts.append(item)
        return "".join(parts)
    return str(content)
