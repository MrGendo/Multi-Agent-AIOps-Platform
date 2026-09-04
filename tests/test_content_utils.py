"""content_utils.extract_text 跨协议内容提取测试.

2026-09-04 生产事故回放: GLM Coding Plan (Anthropic 协议) 返回的
AIMessage.content 是 block 列表, executor 直接 .replace 炸出
'list' object has no attribute 'replace', 整个专家子图降级.
"""

from __future__ import annotations

from app.agents.content_utils import extract_text


class _Msg:
    def __init__(self, content):
        self.content = content


def test_str_content_passthrough():
    assert extract_text(_Msg("hello")) == "hello"


def test_anthropic_blocks():
    msg = _Msg([
        {"type": "thinking", "thinking": "内部推理应被跳过"},
        {"type": "text", "text": "第一段"},
        {"type": "text", "text": "第二段"},
    ])
    assert extract_text(msg) == "第一段第二段"


def test_anthropic_thinking_only():
    # 只有 thinking 块 (极端): 返回空串而不是炸
    msg = _Msg([{"type": "thinking", "thinking": "…"}])
    assert extract_text(msg) == ""


def test_mixed_str_items():
    msg = _Msg(["纯字符串块", {"type": "text", "text": "和文本块"}])
    assert extract_text(msg) == "纯字符串块和文本块"


def test_raw_string_and_other():
    assert extract_text("裸字符串") == "裸字符串"
    assert extract_text(123) == "123"
    assert extract_text(None) == "None"


def test_then_replace_works():
    # 回放事故代码形态: 提取后必须能 .replace
    msg = _Msg([{"type": "text", "text": "line1\nline2"}])
    assert extract_text(msg).replace("\n", " ") == "line1 line2"
