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
        # 嵌套对象数组: 必须把元素的字段形状钉进 prompt — 否则模型自造字段名
        # (2026-10-14 真实事故: attack_chain 元素返回 {stage, action} 而非 {actor, role, ...})
        if type_name == "array" and meta.get("items", {}).get("$ref"):
            lines.append(_nested_items_hint(name, meta, schema))
    return "\n".join(lines)


def _nested_items_hint(name: str, meta: dict, root_schema: dict) -> str:
    """给数组字段的嵌套元素生成「字段名: 形状」样例行 (含一层下钻)."""
    defs = root_schema.get("$defs", {}) or {}
    ref = meta["items"]["$ref"]
    def_key = ref.split("/")[-1]
    sub = defs.get(def_key)
    if not isinstance(sub, dict):
        return ""
    sub_props = sub.get("properties", {})
    if not sub_props:
        return ""
    sub_required = set(sub.get("required", []))
    shape = []
    for fname, fmeta in sub_props.items():
        ftype = fmeta.get("type") or "any"
        req = "必填" if fname in sub_required else "可选"
        shape.append(f'"{fname}"({ftype},{req})')
    return f'    - "{name}" 每个元素必须是 json 对象, 只含这些字段: {", ".join(shape)}'


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


def _coerce_nested_list(value: Any, sub_schema: dict) -> list | None:
    """把 LLM 输出的嵌套数组宽容归一成 sub_schema 形状; 无法挽救返回 None (走原值).

    处理的真实形态 (2026-10-14 GLM 实测):
      - 元素是纯字符串 → 尝试映射到 sub 的第一个必填字段
      - 元素字段名漂移 (stage/step/name/desc) → 按 sub 字段定义挑最接近的键
      - 子字段类型漂移 (remediation 给成字符串) → str→list[str] 拆行 / dict→字段拼接
    """
    if not isinstance(value, list):
        return None
    sub_props: dict = sub_schema.get("properties", {})
    if not sub_props:
        return None
    str_fields = [f for f, m in sub_props.items() if m.get("type") == "string"]
    required = [f for f in sub_schema.get("required", []) if f in sub_props]

    def _fill_missing(item: dict) -> dict | None:
        """补齐缺失的必填 string 字段: 用值最像的字段兜底; 完全无真值则丢弃元素.

        设计取向: {unrelated: 123} 这类一个必填值都凑不出的元素直接丢 (污染),
        但元素只要有至少一个真实必填值, 其余缺的用「未知实体」占位保链 —
        攻击链少一环的上下文损失大于诚实标注的占位 (同 verdict=inconclusive 哲学).
        先扫一遍收集真值 (必填字段处理顺序不影响判定), 再逐个填充.
        """
        def _has_value(fname: str) -> bool:
            v = item.get(fname)
            return isinstance(v, (str, int, float)) and bool(str(v).strip())

        has_any_real = any(_has_value(f) for f in required)
        if not has_any_real:
            # 漂移键也算真值信号 (如 {name: 'SSRF'} 对 vuln 字段)
            drift_keys = ("name", "desc", "description", "title", "entity", "target")
            has_any_real = any(
                isinstance(item.get(k), str) and item[k].strip() for k in drift_keys
            )
        if not has_any_real:
            return None  # 一个必填真值都没有 → 丢元素

        for fname in required:
            if _has_value(fname):
                continue
            # 从漂移键挑值填充 (如 name/desc/description/title 这类常见同义词)
            for alias in ("name", "desc", "description", "title", "entity", "target"):
                if isinstance(item.get(alias), str) and item[alias].strip():
                    item[fname] = item[alias]
                    break
            else:
                # 从未知键的字符串值兜底 (如 {stage:1, action:'...'} 场景的 actor)
                candidates = [
                    v for k, v in item.items()
                    if isinstance(v, str) and v.strip() and k not in sub_props
                ]
                if candidates:
                    item[fname] = candidates[0]
                else:
                    item[fname] = "未知实体"  # 有真值才允许占位 (诚实标注, 不编造)
        return item

    out: list = []
    for el in value:
        if isinstance(el, str):
            # 纯字符串元素: 映射到第一个必填字段
            fname = required[0] if required else (str_fields[0] if str_fields else None)
            if fname and el.strip():
                out.append({fname: el.strip()})
            continue
        if not isinstance(el, dict):
            continue
        # 子字段类型修正: str→list[str] (逗号/分号/换行拆), dict→拼接
        for f, fmeta in sub_props.items():
            if f not in el:
                continue
            v = el[f]
            if fmeta.get("type") == "array" and isinstance(v, str):
                parts = [p.strip(" 、;；\t") for p in re.split(r"[;；\n]|(?<!\d),(?!\d)", v) if p.strip(" 、;；\t")]
                el[f] = parts
            elif fmeta.get("type") == "array" and isinstance(v, dict):
                el[f] = [f"{k}: {val}" for k, val in v.items() if val]
            elif fmeta.get("type") == "string" and isinstance(v, dict):
                parts = [str(x) for x in v.values() if x not in (None, "")]
                el[f] = " - ".join(parts) if parts else ""
            elif fmeta.get("type") == "string" and isinstance(v, list):
                el[f] = " / ".join(str(x) for x in v if x not in (None, ""))
        if _fill_missing(el) is not None:
            out.append(el)
    return out


def _soft_coerce(data: Any, schema_cls: type[BaseModel]) -> Any:
    """按 schema 顶层字段做一次宽松类型修正 (标量/str 列表/嵌套对象数组)."""
    if not isinstance(data, dict):
        return data
    props = schema_cls.model_json_schema().get("properties", {})
    defs = schema_cls.model_json_schema().get("$defs", {}) or {}
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
        # 嵌套对象数组: 字段名/子类型漂移宽容归一 (失败丢元素, 不让整份报告走兜底)
        elif expected == "array" and isinstance(v, list) and meta.get("items", {}).get("$ref"):
            ref = meta["items"]["$ref"]
            sub = defs.get(ref.split("/")[-1])
            if isinstance(sub, dict):
                coerced = _coerce_nested_list(v, sub)
                if coerced is not None:
                    out[name] = coerced
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
