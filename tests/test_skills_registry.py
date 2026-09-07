"""Skill 注册表与新登记 Skill 的离线校验.

覆盖:
  - registry 全量加载 7 个 skill (含 database_diagnosis / k8s_diagnosis, generic_oncall 兜底仍在)
  - 两个新 skill 的 frontmatter 字段完整性
  - 新 skill 的 allowed_tools ⊆ TOOL_META 已登记工具集 (不硬编码名单)
  - Router 系统提示与菜单均已登记两个新 skill

离线红线: 只读模块级单例与字符串, 不碰 LLM / Milvus / Redis / 网络.
"""

from __future__ import annotations

from typing import get_args

from app.runtime.agent_harness import AgentHarness
from app.skills.models import RiskLevel
from app.skills.registry import get_skill_registry
from app.tools.meta import TOOL_META

# 本任务新增的两个 Skill
NEW_SKILLS = ("database_diagnosis", "k8s_diagnosis")

# 5 个存量 + 2 个新增
EXPECTED_SKILL_COUNT = 7

# RiskLevel 是 Literal["low", "medium", "high"], 直接取其字面量集合
VALID_RISK_LEVELS = set(get_args(RiskLevel))


def test_registry_loads_seven_skills():
    """加载后应有 7 个 skill, 新增两个在场, generic_oncall 兜底仍在."""
    names = set(get_skill_registry().names())
    assert len(names) == EXPECTED_SKILL_COUNT
    assert {"database_diagnosis", "k8s_diagnosis", "generic_oncall"} <= names


def test_new_skills_frontmatter_complete():
    """两个新 skill 的 frontmatter 必填字段齐全且取值合法."""
    registry = get_skill_registry()
    for name in NEW_SKILLS:
        skill = registry.get(name)
        assert skill is not None, f"{name} 未被 registry 加载"
        assert skill.name == name
        assert skill.display_name, f"{name} display_name 为空"
        assert skill.description, f"{name} description 为空"
        assert skill.triggers, f"{name} triggers 为空"
        assert skill.allowed_tools, f"{name} allowed_tools 为空"
        assert skill.risk_level in VALID_RISK_LEVELS
        assert skill.playbook.strip(), f"{name} playbook 为空"


def test_new_skills_allowed_tools_registered():
    """新 skill 的 allowed_tools 必须都在 TOOL_META 里 (不允许引未登记工具)."""
    registry = get_skill_registry()
    registered = set(TOOL_META)
    for name in NEW_SKILLS:
        skill = registry.get(name)
        assert skill is not None
        unknown = set(skill.allowed_tools) - registered
        assert not unknown, f"{name} allowed_tools 未在 TOOL_META 登记: {sorted(unknown)}"


def test_router_prompt_and_menu_include_new_skills():
    """Router 系统提示与生成的菜单都要包含两个新 skill 名."""
    prompt = AgentHarness._SKILL_ROUTER_SYSTEM_PROMPT
    assert "database_diagnosis" in prompt
    assert "k8s_diagnosis" in prompt
    menu = get_skill_registry().to_router_menu()
    assert "database_diagnosis" in menu
    assert "k8s_diagnosis" in menu
