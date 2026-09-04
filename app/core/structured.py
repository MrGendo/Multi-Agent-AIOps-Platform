"""结构化输出兼容层.

统一使用 response_format={"type": "json_object"} + Pydantic 校验, 避免部分
OpenAI 兼容接口不支持 SDK Pydantic parse response_format.
"""

from __future__ import annotations

import json
import re
from typing import Any, TypeVar

from langchain_core.language_models import BaseChatModel
from loguru import logger
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


def is_deepseek_model(model: str | None) -> bool:
    return bool((model or "").lower().startswith("deepseek"))


def _schema_hint(schema_cls: type[BaseModel]) -> str:
    schema = schema_cls.model_json_schema()
    props = schema.get("properties", {})
    required = set(schema.get("required", []))
    lines = []
    for name, meta in props.items():
        type_name = meta.get("type") or meta.get("anyOf") or "any"
        req = "必填" if name in required else "可选"
        desc = meta.get("description", "")
        lines.append(f'- "{name}" ({req}, {type_name}): {desc}')
    return "\n".join(lines)


def _extract_json(text: str) -> dict[str, Any]:
    raw = (text or "").strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.IGNORECASE)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", raw, flags=re.DOTALL)
        if not match:
            raise
        return json.loads(match.group(0))


def _coerce_scalar(value: Any, expected: str) -> Any:
    """宽松修正 LLM 输出的标量类型不匹配 (Plan.steps 出现 dict/int 等).

    Anthropic 协议路径没有 response_format 强约束, 模型偶尔返回
    {"step": 6, "name": "..."} 这类结构 — 收敛成字符串保住可用性.
    """
    if expected == "string" and not isinstance(value, str):
        if isinstance(value, dict):
            parts = [str(v) for v in value.values() if v not in (None, "")]
            return " - ".join(parts) if parts else str(value)
        return str(value)
    if expected == "integer" and isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    if expected == "number" and isinstance(value, (int, float)):
        return value
    if expected == "boolean" and isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "1", "是")
    return value


def _soft_coerce(data: Any, schema_cls: type[BaseModel]) -> Any:
    """按 schema 顶层字段做一次宽松类型修正 (只动标量与 str 列表元素)."""
    if not isinstance(data, dict):
        return data
    props = schema_cls.model_json_schema().get("properties", {})
    out = dict(data)
    for name, meta in props.items():
        if name not in out:
            continue
        expected = meta.get("type")
        v = out[name]
        if expected == "array" and isinstance(v, list) and meta.get("items", {}).get("type") == "string":
            out[name] = [_coerce_scalar(x, "string") if not isinstance(x, str) else x for x in v]
        elif expected in ("string", "integer", "number", "boolean"):
            out[name] = _coerce_scalar(v, expected)
    return out


async def ainvoke_structured(
    *,
    llm: BaseChatModel,
    schema_cls: type[T],
    messages: list[dict[str, str]],
    model_name: str | None,
) -> T:
    """调用 LLM 并返回 Pydantic 对象.

    所有模型统一走 JSON 文本解析, 避免部分 OpenAI 兼容接口不支持 SDK Pydantic parse.
    """
    # 注意: DashScope 兼容接口对 response_format=json_object 有一个硬约束 —
    # messages 里必须出现**小写** "json" 字样, 否则返回 400
    #   "messages must contain the word 'json' in some form".
    # OpenAI 官方校验是大小写不敏感的, DashScope 的实现更严, 这里统一用小写, 并多写几次保险.
    json_instruction = {
        "role": "system",
        "content": (
            "你必须只输出一个合法的 json 对象 (严格 json 格式, 小写 json), "
            "不要 markdown, 不要代码块, 不要解释。\n"
            "json 字段要求:\n"
            f"{_schema_hint(schema_cls)}"
        ),
    }

    # ChatOpenAI 系支持 response_format=json_object 强约束输出;
    # ChatAnthropic (GLM Coding Plan 走此协议) 不支持该绑定, 靠 prompt 约束.
    # 两者都靠 _extract_json 兜底提取 JSON 文本.
    llm_cls_name = type(llm).__name__
    if "Anthropic" in llm_cls_name:
        json_llm = llm
    else:
        json_llm = llm.bind(response_format={"type": "json_object"})
    resp = await json_llm.ainvoke([json_instruction, *messages])
    content = getattr(resp, "content", resp)
    if isinstance(content, list):
        # Anthropic 协议: content 是 block 列表, 取 text 块 (跳过 thinking 块)
        text = "".join(
            item.get("text", "") if isinstance(item, dict) and item.get("type") == "text"
            else str(item) if not isinstance(item, dict) else ""
            for item in content
        )
    else:
        text = str(content)
    data = _extract_json(text)
    data = _unwrap_envelope(data, schema_cls)
    try:
        obj = schema_cls.model_validate(data)
    except Exception:
        # 宽松修正一轮再试 (Anthropic 路径无 response_format 强约束时需要)
        obj = schema_cls.model_validate(_soft_coerce(data, schema_cls))
    logger.debug(f"[structured] JSON parsed as {schema_cls.__name__}: {obj}")
    return obj


def _unwrap_envelope(data: Any, schema_cls: type) -> Any:
    """剥掉 LLM 常见的包裹层 (answer/data/result 等单键包裹).

    GLM/部分模型即使给了 json_object 指令, 也会返回 {"answer": {...期望结构...}}.
    判定: dict 且只有一个键, 键名在常见包裹词表内, 且内层是 dict 且
    至少有一个键能对上目标 schema 的字段 — 才把内层提出来再校验.
    """
    if not isinstance(data, dict) or len(data) != 1:
        return data
    key = next(iter(data))
    inner = data[key]
    if not isinstance(inner, dict):
        return data
    if key.lower() in ("answer", "data", "result", "results", "output", "response", "输出", "结果", "回答"):
        schema_fields = set(getattr(schema_cls, "model_fields", {}) or {})
        if not schema_fields or (set(inner) & schema_fields):
            logger.debug(f"[structured] 剥掉包裹层 {{'{key}': ...}}")
            return inner
    return data
