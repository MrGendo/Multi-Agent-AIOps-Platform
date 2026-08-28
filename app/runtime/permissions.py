"""三态权限决策 (PermissionMode + PermissionDecision + evaluate_permission).

§1 cc-haha 借鉴: 把 Harness 从单层白名单升级到三层防御.

四个 PermissionMode:
  - READ_ONLY        只允许 ToolMeta.read_only=True 的工具 (演示沙箱)
  - NORMAL           当前默认: Skill 白名单 + 高危/通知黑名单 (生产)
  - ASK_DESTRUCTIVE  写/通知工具走人工审批
  - BYPASS           dev only, 跳过所有非硬墙检查 (绝不在生产打开)

每次决策返回 PermissionDecision { behavior, reason_type, reason }, 三态:
  - allow:  正常调用
  - ask:    需要人工审批 (MVP 阶段直接转 deny)
  - deny:   拒绝调用

设计原则:
  - 硬墙优先: Skill allowed_tools 不在 → 立刻 deny (不受 mode 影响)
  - fail-closed: 未登记工具按保守默认 (非只读) 处理
  - 决策可解释: 每个 deny/ask 都带 reason_type 枚举, 排错和审计都好用

参考:
  cc-haha src/Tool.ts:494-516 PermissionResult
  cc-haha docs/agent/03-agent-framework.md:471-520 4 layer defense
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Set

from pydantic import BaseModel, Field

from app.tools.meta import get_meta


# ============================================================
# Mode + Decision
# ============================================================
class PermissionMode(str, Enum):
    """运行时权限模式.

    通过 settings.permission_mode (env: PERMISSION_MODE) 或 state["permission_mode"]
    在每次诊断会话粒度切换. 默认 NORMAL.
    """

    READ_ONLY = "read_only"
    NORMAL = "normal"
    ASK_DESTRUCTIVE = "ask_destructive"
    BYPASS = "bypass"


# 决策原因枚举: 排错和审计直接 grep reason_type
ReasonType = Literal[
    "skill_allowlist",  # Skill allowed_tools 不含 (硬墙)
    "guardrail_high",  # 高危黑名单 (NORMAL 模式默认拦截)
    "guardrail_notify",  # 通知类未授权 (NORMAL 模式默认拦截)
    "mode_read_only",  # READ_ONLY 模式拒绝写工具
    "mode_ask",  # ASK_DESTRUCTIVE 模式触发审批
    "mode_bypass",  # BYPASS 模式直通 (仅 dev)
    "rule_param",  # 参数级规则 (占位, MVP 不实现)
    "ok",  # allow
]


class PermissionDecision(BaseModel):
    """一次工具调用的权限判定结果."""

    behavior: Literal["allow", "ask", "deny"]
    reason_type: ReasonType
    reason: str = ""
    suggestions: List[str] = Field(default_factory=list)
    # 占位: cc-haha 支持运行时改写 tool_input. MVP 不实现.
    updated_input: Optional[Dict[str, Any]] = None

    def is_allowed(self) -> bool:
        return self.behavior == "allow"

    def is_blocked(self) -> bool:
        """ask 也算 blocked, 因为 MVP 阶段 ask 会转成 deny 给 LLM 看到."""
        return self.behavior in ("ask", "deny")


# ============================================================
# Layer 3: 参数级规则
# ============================================================
# 规则形如 "docker_restart(container=nginx-*)" — 工具名 + 关键参数 glob 白名单.
# 语义: 该工具只有在指定参数匹配白名单时才允许; 否则 deny (reason_type=rule_param).
# 预决策 (bind_tools 阶段, tool_input=None): 规则存在 → ask (保守, 等 args 到了再判).
ParamRule = Dict[str, Any]  # {"tool": str, "param": str, "allowed_patterns": [str]}

_PARAM_RULES: List[ParamRule] = []


def register_param_rule(tool: str, param: str, allowed_patterns: List[str]) -> None:
    """注册参数级规则 (幂等: 同 tool+param 覆盖).

    例: register_param_rule("docker_restart", "container", ["nginx-*", "redis-*"])
    """
    global _PARAM_RULES
    _PARAM_RULES = [
        r for r in _PARAM_RULES if not (r["tool"] == tool and r["param"] == param)
    ] + [{"tool": tool, "param": param, "allowed_patterns": list(allowed_patterns)}]


def clear_param_rules() -> None:
    """清空规则 (测试用)."""
    global _PARAM_RULES
    _PARAM_RULES = []


def _match_param_rules(tool_name: str, tool_input: Optional[Dict[str, Any]]):
    """返回该工具的参数规则 (无则 None). tool_input=None 表示预决策阶段."""
    rules = [r for r in _PARAM_RULES if r["tool"] == tool_name]
    if not rules:
        return None
    return rules


def _fnmatch_any(value: str, patterns: List[str]) -> bool:
    from fnmatch import fnmatchcase

    return any(fnmatchcase(value, p) for p in patterns)


def _evaluate_param_rules(
    tool_name: str, tool_input: Optional[Dict[str, Any]]
) -> Optional[PermissionDecision]:
    """Layer 3 决策. 返回 None 表示无规则适用 (放行到默认 allow)."""
    rules = _match_param_rules(tool_name, tool_input)
    if rules is None:
        return None

    # 预决策阶段 (bind_tools): 参数未知 → ask, 让调用方在拿到真实 args 后复查
    if tool_input is None:
        return PermissionDecision(
            behavior="ask",
            reason_type="rule_param",
            reason=f"工具 {tool_name!r} 有参数级规则, 需在调用时按参数复查",
        )

    for rule in rules:
        param = rule["param"]
        value = tool_input.get(param)
        if value is None:
            return PermissionDecision(
                behavior="deny",
                reason_type="rule_param",
                reason=f"工具 {tool_name!r} 要求参数 {param!r}, 但调用未提供",
            )
        if not _fnmatch_any(str(value), rule["allowed_patterns"]):
            return PermissionDecision(
                behavior="deny",
                reason_type="rule_param",
                reason=(
                    f"工具 {tool_name!r} 参数 {param}={value!r} 不在允许列表 "
                    f"{rule['allowed_patterns']} 内"
                ),
            )
    return None  # 全部规则通过


# ============================================================
# 决策函数
# ============================================================
# 注意: 这些集合从 tool_filter 获取, 但为了避免循环 import 用延迟 import
def _get_high_risk_set() -> Set[str]:
    from app.runtime.tool_filter import HIGH_RISK_TOOLS

    return HIGH_RISK_TOOLS


def _get_notification_set() -> Set[str]:
    from app.runtime.tool_filter import NOTIFICATION_TOOLS

    return NOTIFICATION_TOOLS


def evaluate_permission(
    tool_name: str,
    tool_input: Optional[Dict[str, Any]] = None,
    *,
    skill_allowed: Set[str],
    mode: PermissionMode = PermissionMode.NORMAL,
    block_high_risk: bool = True,
    allow_notification: bool = False,
) -> PermissionDecision:
    """三层防御决策.

    决策顺序 (短路返回):
      Layer 0: Skill allowlist (硬墙) - 任何 mode 都得过这关
      Layer 1: Mode 限制
      Layer 2: 静态 Guardrails (高危/通知黑名单)
      Layer 3: (占位) 参数级规则

    Args:
        tool_name: 工具名
        tool_input: 工具入参 (留给 ToolMeta.is_read_only_for_input 输入感知用)
        skill_allowed: 当前 Skill 声明的 allowed_tools 集合
        mode: 当前运行时模式
        block_high_risk: 是否启用高危黑名单 (settings.guardrails_block_high_risk_tools)
        allow_notification: 是否允许通知类工具 (settings.guardrails_allow_notification_tools)

    Returns:
        PermissionDecision (behavior + reason_type + reason)
    """
    meta = get_meta(tool_name)  # 未登记工具走保守默认 (read_only=False)

    # ---- Layer 0: Skill 硬墙 (任何 mode 都不能绕过) ----
    # 策略调整 (2026-05-02): 只读查询工具 (ToolMeta.read_only=True) 豁免 Skill 白名单,
    # 允许任何 Skill 下使用. 动机:
    #   - 诊断类 Skill 经常漏写某个本机指标工具 (如 list_top_processes), 会导致 Agent
    #     调用时被硬墙挡住, 诊断报告只能编造 "未提供 MCP 工具".
    #   - 只读工具无副作用, 放开跨 Skill 使用是安全的.
    #   - 写/通知/高危工具仍然严格受 Skill 白名单 + Guardrails + Mode 多层控制.
    # 输入感知: 某些工具 (如 Bash) read_only 取决于入参, 用 effective_read_only 判断.
    if tool_name not in skill_allowed and not meta.effective_read_only(tool_input):
        return PermissionDecision(
            behavior="deny",
            reason_type="skill_allowlist",
            reason=f"工具 {tool_name!r} 不在当前 Skill 的 allowed_tools 中",
        )

    # ---- Layer 3 (预判): 参数级规则在 BYPASS 之前 —
    # 参数白名单是硬约束 (比 mode 更细), 连 BYPASS 也不放行白名单外的参数.
    # 预决策 (无 args) 在 BYPASS 下直接放行, 运行时再按真实 args 复查.
    if tool_input is not None:
        param_decision = _evaluate_param_rules(tool_name, tool_input)
        if param_decision is not None and param_decision.behavior != "allow":
            return param_decision

    # ---- BYPASS 模式: 跳过其余所有检查 (生产绝不打开) ----
    if mode == PermissionMode.BYPASS:
        param_pre = _evaluate_param_rules(tool_name, None)
        if param_pre is not None:
            # 有规则但参数未知: BYPASS 下不挂起 (dev 直通), 运行时复查兜底
            return PermissionDecision(
                behavior="allow",
                reason_type="mode_bypass",
                reason="BYPASS 模式直通 (参数级规则将由运行时复查)",
            )
        return PermissionDecision(
            behavior="allow",
            reason_type="mode_bypass",
            reason="BYPASS 模式直通 (仅限 dev)",
        )

    # ---- Layer 1: Mode 限制 ----
    # 输入感知 read_only: 比如 Bash(ls) 只读, Bash(rm) 不只读
    effective_read_only = meta.effective_read_only(tool_input)

    if mode == PermissionMode.READ_ONLY and not effective_read_only:
        return PermissionDecision(
            behavior="deny",
            reason_type="mode_read_only",
            reason=f"READ_ONLY 模式只允许只读工具, {tool_name!r} 涉及写操作 / 副作用",
        )

    if mode == PermissionMode.ASK_DESTRUCTIVE:
        # 写工具或通知工具 → 走人工审批
        if meta.destructive or meta.is_notification or tool_name in _get_high_risk_set():
            return PermissionDecision(
                behavior="ask",
                reason_type="mode_ask",
                reason=f"ASK_DESTRUCTIVE 模式: {tool_name!r} 是写/通知操作, 需人工确认",
                suggestions=["允许一次", "本会话总是允许", "拒绝"],
            )

    # ---- Layer 2: 静态 Guardrails (与原 _is_tool_allowed_by_guardrails 等价) ----
    # 例外: 非破坏性的高危工具被 Skill 的 allowed_tools 显式声明 = 维护者人工批准.
    # 否则会出现「SKILL.md 写了沙箱工具但运行时永远被拦」的死配置 —
    # 典型受害者是 execute_python_script (README 核心卖点, 但任何技能都未声明,
    # 双层防御正确拒绝 → LLM 白白烧一轮往返). 人工声明 > 静态黑名单.
    # 破坏性工具 (docker_restart 等) 不享受此例外: 沙箱有自己的隔离层
    # (rlimits/黑名单/cwd), 破坏性工具没有.
    if (
        block_high_risk
        and tool_name in _get_high_risk_set()
        and (meta.destructive or tool_name not in skill_allowed)
    ):
        return PermissionDecision(
            behavior="deny",
            reason_type="guardrail_high",
            reason=f"高危工具 {tool_name!r} 被默认拦截 (settings.guardrails_block_high_risk_tools=True)",
        )

    if not allow_notification and tool_name in _get_notification_set():
        return PermissionDecision(
            behavior="deny",
            reason_type="guardrail_notify",
            reason=f"通知类工具 {tool_name!r} 未授权 (settings.guardrails_allow_notification_tools=False)",
        )

    # ---- Layer 3: 参数级规则 ----
    # 有 tool_input (真实调用) → 按 glob 白名单判; 无 (bind 预决策) → ask 保守挂起
    param_decision = _evaluate_param_rules(tool_name, tool_input)
    if param_decision is not None and param_decision.behavior != "allow":
        return param_decision

    # ---- Allow ----
    return PermissionDecision(
        behavior="allow",
        reason_type="ok",
        reason="",
    )


def parse_permission_mode(value: Optional[str]) -> PermissionMode:
    """容错解析 mode 字符串. 未知值降级为 NORMAL."""
    if not value:
        return PermissionMode.NORMAL
    try:
        return PermissionMode(value.lower().strip())
    except ValueError:
        return PermissionMode.NORMAL
