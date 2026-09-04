"""结构化输出包裹层剥离测试 (GLM 实测发现的 {answer:{...}} 形态).

回放 2026-09-04 真实故障: GLM 返回 {"answer": {"steps": [...]}} 导致
Plan 校验失败 → 误走推理兜底 → 工具全跳过.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.core.structured import _unwrap_envelope


class _Plan(BaseModel):
    steps: list = Field(default_factory=list)


class _Choice(BaseModel):
    is_oncall: bool = False
    skill_names: list = Field(default_factory=list)


def test_answer_envelope_unwrapped():
    data = {"answer": {"steps": ["查CPU", "查内存"]}}
    assert _unwrap_envelope(data, _Plan) == {"steps": ["查CPU", "查内存"]}


def test_data_envelope_unwrapped():
    data = {"data": {"is_oncall": True, "skill_names": ["x"]}}
    assert _unwrap_envelope(data, _Choice) == {"is_oncall": True, "skill_names": ["x"]}


def test_chinese_key_envelope_unwrapped():
    data = {"输出": {"steps": ["s1"]}}
    assert _unwrap_envelope(data, _Plan) == {"steps": ["s1"]}


def test_envelope_inner_must_match_schema():
    # 单键 data 但内层对不上 schema 字段 → 不剥 (防误剥正常结构)
    data = {"data": {"unrelated": 1}}
    assert _unwrap_envelope(data, _Plan) == data


def test_no_envelope_untouched():
    data = {"steps": ["s"], "other": 1}  # 多键, 不是包裹层
    assert _unwrap_envelope(data, _Plan) == data


def test_non_dict_passthrough():
    assert _unwrap_envelope(["a"], _Plan) == ["a"]
    assert _unwrap_envelope("x", _Plan) == "x"


def test_scalar_envelope_untouched():
    # {"answer": "文本"} 内层不是 dict → 不剥
    data = {"answer": "纯文本"}
    assert _unwrap_envelope(data, _Plan) == data
