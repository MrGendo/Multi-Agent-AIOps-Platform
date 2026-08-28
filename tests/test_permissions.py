"""app.runtime.permissions: 三态权限决策 (allow / ask / deny) 测试."""

from __future__ import annotations

from app.runtime.permissions import (
    PermissionDecision,
    PermissionMode,
    evaluate_permission,
    parse_permission_mode,
)

READ_ONLY_TOOL = "get_local_cpu_memory"    # read_only=True
WRITE_TOOL = "docker_restart"              # destructive, risk=high
SANDBOX_TOOL = "execute_python_script"     # risk=high, 非只读
UNREGISTERED = "no_such_tool_abc"


def test_skill_allowlist_hardwall_denies():
    # Layer 0: 不在 skill_allowed 且非只读 → deny (硬墙)
    d = evaluate_permission(WRITE_TOOL, skill_allowed={"other_tool"})
    assert d.behavior == "deny"
    assert d.reason_type == "skill_allowlist"
    assert d.is_blocked()
    assert not d.is_allowed()


def test_readonly_tool_exempt_from_allowlist():
    # 只读工具豁免 Skill 白名单 (2026-05-02 策略)
    d = evaluate_permission(READ_ONLY_TOOL, skill_allowed=set())
    assert d.behavior == "allow"
    assert d.reason_type == "ok"


def test_unregistered_tool_fail_closed():
    # 未登记 → 保守默认非只读 → 被 Layer 0 拒 (不在白名单时)
    d = evaluate_permission(UNREGISTERED, skill_allowed={"x"})
    assert d.behavior == "deny"
    assert d.reason_type == "skill_allowlist"


def test_high_risk_tool_denied_in_normal_mode():
    # docker_restart 在白名单中, 但 risk=high + destructive → guardrail_high 拦截
    d = evaluate_permission(WRITE_TOOL, skill_allowed={WRITE_TOOL})
    assert d.behavior == "deny"
    assert d.reason_type == "guardrail_high"


def test_high_risk_allowed_when_guardrail_disabled():
    d = evaluate_permission(
        WRITE_TOOL,
        skill_allowed={WRITE_TOOL},
        block_high_risk=False,
    )
    assert d.behavior == "allow"


def test_read_only_mode_denies_write_tools():
    d = evaluate_permission(
        WRITE_TOOL,
        skill_allowed={WRITE_TOOL},
        mode=PermissionMode.READ_ONLY,
        block_high_risk=False,
    )
    assert d.behavior == "deny"
    assert d.reason_type == "mode_read_only"


def test_read_only_mode_allows_readonly_tools():
    d = evaluate_permission(
        READ_ONLY_TOOL,
        skill_allowed=set(),
        mode=PermissionMode.READ_ONLY,
    )
    assert d.behavior == "allow"


def test_ask_destructive_mode_asks_for_write_tools():
    d = evaluate_permission(
        WRITE_TOOL,
        skill_allowed={WRITE_TOOL},
        mode=PermissionMode.ASK_DESTRUCTIVE,
        block_high_risk=False,
    )
    assert d.behavior == "ask"
    assert d.reason_type == "mode_ask"
    assert d.is_blocked()  # ask 也算 blocked (MVP 转 deny)
    assert d.suggestions  # 带 "允许一次" 等选项


def test_bypass_mode_allows_everything_in_allowlist():
    d = evaluate_permission(
        WRITE_TOOL,
        skill_allowed={WRITE_TOOL},
        mode=PermissionMode.BYPASS,
    )
    assert d.behavior == "allow"
    assert d.reason_type == "mode_bypass"


def test_bypass_cannot_cross_skill_hardwall():
    # BYPASS 也不能绕过 Layer 0 硬墙
    d = evaluate_permission(
        WRITE_TOOL,
        skill_allowed={"unrelated"},
        mode=PermissionMode.BYPASS,
    )
    assert d.behavior == "deny"
    assert d.reason_type == "skill_allowlist"


def test_notification_tool_denied_by_default():
    # 构造一个通知类工具的决策 (当前 TOOL_META 无通知工具, 用 evaluate 逻辑验证开关关闭时行为)
    d = evaluate_permission(
        READ_ONLY_TOOL,
        skill_allowed=set(),
        allow_notification=False,
    )
    assert d.behavior == "allow"  # 非通知工具不受该开关影响


def test_decision_helpers():
    allow = PermissionDecision(behavior="allow", reason_type="ok")
    deny = PermissionDecision(behavior="deny", reason_type="skill_allowlist")
    ask = PermissionDecision(behavior="ask", reason_type="mode_ask")
    assert allow.is_allowed() and not allow.is_blocked()
    assert not deny.is_allowed() and deny.is_blocked()
    assert not ask.is_allowed() and ask.is_blocked()


def test_parse_permission_mode_fallbacks():
    assert parse_permission_mode(None) is PermissionMode.NORMAL
    assert parse_permission_mode("") is PermissionMode.NORMAL
    assert parse_permission_mode("READ_ONLY") is PermissionMode.READ_ONLY
    assert parse_permission_mode("  bypass  ") is PermissionMode.BYPASS
    assert parse_permission_mode("garbage") is PermissionMode.NORMAL  # 未知降级


# ============================================================
# 高危工具的 skill 白名单例外 (2026-08-28 E2E 发现的死配置修复)
# ============================================================
def test_high_risk_non_destructive_allowed_when_skill_declares():
    # 沙箱: risk=high, 非破坏性 (有自己的隔离层) + skill 显式声明 → 放行
    d = evaluate_permission("execute_python_script", skill_allowed={"execute_python_script"})
    assert d.behavior == "allow", d.reason


def test_high_risk_non_destructive_still_denied_without_declaration():
    # 未声明 → 仍被 guardrail 拦截 (例外必须显式声明才生效)
    d = evaluate_permission("execute_python_script", skill_allowed=set())
    assert d.behavior == "deny"
    assert d.reason_type == "guardrail_high"


def test_destructive_high_risk_never_gets_exception():
    # 破坏性工具即使 skill 声明也拦 (docker_restart 类)
    d = evaluate_permission(WRITE_TOOL, skill_allowed={WRITE_TOOL})
    assert d.behavior == "deny"
    assert d.reason_type == "guardrail_high"
