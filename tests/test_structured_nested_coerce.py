"""结构化输出嵌套数组宽容归一测试 (2026-10-14 真实故障回放).

故障: SecOps FactSheet 加 attack_chain/vuln_explains 嵌套字段后, GLM 返回:
  - attack_chain 元素用自造字段 {stage, action} 而非 {actor, role, action, ...}
  - vuln_explains.0 用 {name} 而非 {vuln}, remediation 给成纯字符串
  - response_actions 元素是纯字符串 "[observe] 持续观察..."
三形态全部 12 validation errors → 整份报告走规则模板兜底, 攻击链丢失.

修法: _schema_hint 钉嵌套元素字段形状 + _soft_coerce 嵌套数组宽容归一
(归一失败丢元素, 不让整份报告走兜底).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.core.structured import _coerce_nested_list, _schema_hint, _soft_coerce


class _Rec(BaseModel):
    actor: str = Field(..., description="实体名")
    role: str = Field(default="pivot", description="角色")
    action: str = Field(..., description="行为")
    mitre: str = Field(default="", description="技术ID")


class _Vuln(BaseModel):
    vuln: str = Field(..., description="漏洞名")
    principle: str = Field(..., description="原理")
    remediation: list = Field(default_factory=list, description="修复")


class _Sheet(BaseModel):
    summary: str = ""
    attack_chain: list[_Rec] = Field(default_factory=list)
    vuln_explains: list[_Vuln] = Field(default_factory=list)


def test_nested_items_hint_pins_field_shapes():
    """schema hint 必须含嵌套元素字段形状 (attack_chain: actor/role/action/mitre)."""
    hint = _schema_hint(_Sheet)
    assert '"attack_chain" 每个元素必须是 json 对象' in hint
    assert '"actor"(string,必填)' in hint
    assert '"role"(string,可选)' in hint
    assert '"vuln_explains" 每个元素必须是 json 对象' in hint
    assert '"remediation"(array,可选)' in hint


def test_coerce_drifted_field_names():
    """回放: {stage, action} → actor 兜底填充, 校验通过."""
    data = {
        "summary": "s",
        "attack_chain": [
            {"stage": 1, "action": "构造恶意 URL"},
            {"stage": 2, "action": "服务端发起内网请求", "role": "pivot"},
        ],
    }
    out = _soft_coerce(data, _Sheet)
    obj = _Sheet.model_validate(out)
    assert len(obj.attack_chain) == 2
    assert obj.attack_chain[0].actor  # 从 stage/action 之外的值兜底 (这里是 action 之外的漂移键场景)
    assert obj.attack_chain[0].action == "构造恶意 URL"


def test_coerce_string_remediation_split():
    """回放: remediation 纯字符串 → 拆成 list[str]."""
    data = {
        "vuln_explains": [
            {
                "name": "SSRF",
                "principle": "服务器替用户访问任意网址",
                "remediation": "url 参数白名单；内网段隔离；协议校验",
            }
        ],
    }
    out = _soft_coerce(data, _Sheet)
    obj = _Sheet.model_validate(out)
    assert obj.vuln_explains[0].vuln == "SSRF"  # name → vuln 漂移修复
    assert isinstance(obj.vuln_explains[0].remediation, list)
    assert len(obj.vuln_explains[0].remediation) == 3
    assert "url 参数白名单" in obj.vuln_explains[0].remediation[0]


def test_coerce_pure_string_elements():
    """回放: response_actions 纯字符串元素 → 映射到第一个必填字段."""
    sub_schema = {
        "properties": {
            "action": {"type": "string"},
            "rationale": {"type": "string"},
            "requires_approval": {"type": "boolean"},
        },
        "required": ["action"],
    }
    out = _coerce_nested_list(["[observe] 持续观察该来源", "[recommend] 建议核查"], sub_schema)
    assert out == [
        {"action": "[observe] 持续观察该来源"},
        {"action": "[recommend] 建议核查"},
    ]


def test_coerce_drop_unsalvageable_element():
    """一个必填真值都没有的元素被丢弃, 其余保留 (丢元素不丢整份报告)."""
    sub_schema = {
        "properties": {"actor": {"type": "string"}, "action": {"type": "string"}},
        "required": ["actor", "action"],
    }
    out = _coerce_nested_list(
        [{"actor": "攻击者", "action": "构造 URL"}, {"unrelated": 123}],
        sub_schema,
    )
    assert out == [{"actor": "攻击者", "action": "构造 URL"}]


def test_coerce_placeholder_keeps_chain_step():
    """元素有真值但部分必填缺失 → 「未知实体」占位保链 (诚实标注不编造)."""
    sub_schema = {
        "properties": {"actor": {"type": "string"}, "action": {"type": "string"}},
        "required": ["actor", "action"],
    }
    out = _coerce_nested_list([{"action": "服务端发起内网请求"}], sub_schema)
    assert out == [{"action": "服务端发起内网请求", "actor": "未知实体"}]


def test_coerce_non_list_returns_none():
    """非 list 输入返回 None (走原值, 由 pydantic 报错)."""
    assert _coerce_nested_list("not a list", {"properties": {"a": {"type": "string"}}}) is None
    assert _coerce_nested_list([1, 2], {}) is None
