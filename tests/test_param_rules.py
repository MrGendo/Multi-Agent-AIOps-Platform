"""Layer 3 参数级权限规则测试.

两段式:
  1. evaluate_permission 决策函数: glob 白名单判定 (允许/拒绝/缺参数/预决策 ask)
  2. tool_runner 运行时复查: bind 预决策标记的工具, 拿真实 args 重判

场景: docker_restart(container=...) 只允许重启 nginx-*/redis-* 容器.
"""

from __future__ import annotations

import pytest

from app.runtime.permissions import (
    PermissionMode,
    clear_param_rules,
    evaluate_permission,
    register_param_rule,
)


@pytest.fixture(autouse=True)
def _docker_rule():
    register_param_rule("docker_restart", "container", ["nginx-*", "redis-*"])
    yield
    clear_param_rules()


ALLOWED = {"docker_restart"}  # 模拟 skill 白名单已声明


def test_allowed_pattern_passes():
    d = evaluate_permission(
        "docker_restart",
        {"container": "nginx-proxy"},
        skill_allowed=ALLOWED,
        mode=PermissionMode.BYPASS,
    )
    assert d.behavior == "allow", d.reason


def test_disallowed_pattern_denied():
    d = evaluate_permission(
        "docker_restart",
        {"container": "postgres-db"},  # 不在白名单
        skill_allowed=ALLOWED,
        mode=PermissionMode.BYPASS,
    )
    assert d.behavior == "deny"
    assert d.reason_type == "rule_param"
    assert "postgres-db" in d.reason  # 拒绝理由带具体值, LLM 能自我纠正


def test_missing_param_denied():
    d = evaluate_permission(
        "docker_restart",
        {},  # 没传 container
        skill_allowed=ALLOWED,
        mode=PermissionMode.BYPASS,
    )
    assert d.behavior == "deny"
    assert d.reason_type == "rule_param"
    assert "container" in d.reason


def test_predecision_without_args_asks():
    # bind_tools 阶段无参数 → ask (保守, 等运行时拿 args 重判)
    # (NORMAL 模式下; BYPASS 下预决策直通由运行时复查兜底)
    d = evaluate_permission(
        "docker_restart",
        None,
        skill_allowed=ALLOWED,
        mode=PermissionMode.NORMAL,
        block_high_risk=False,
    )
    assert d.behavior == "ask"
    assert d.reason_type == "rule_param"


def test_no_rule_unaffected():
    # 无规则的工具行为不变 (回归: Layer 3 不影响存量语义)
    d = evaluate_permission(
        "get_local_cpu_memory",
        {"seconds": 5},
        skill_allowed={"get_local_cpu_memory"},
        mode=PermissionMode.NORMAL,
    )
    assert d.behavior == "allow"


def test_rule_registration_idempotent():
    register_param_rule("docker_restart", "container", ["only-this"])
    d = evaluate_permission(
        "docker_restart",
        {"container": "nginx-proxy"},  # 旧白名单不再生效
        skill_allowed=ALLOWED,
        mode=PermissionMode.BYPASS,
    )
    assert d.behavior == "deny"


# ============================================================
# tool_runner 运行时复查 (集成)
# ============================================================
async def test_runner_recheck_blocks_disallowed_container(monkeypatch):
    """bind 预决策 ask → 运行时 args 复查: 白名单内放行 / 白名单外拒绝."""
    from langchain_core.messages import AIMessage

    from app.runtime.tool_runner import run_parallel_agent

    calls = []

    class _LLM:
        def __init__(self):
            self.round = 0

        def bind_tools(self, tools):
            return self

        async def astream(self, messages):
            self.round += 1
            if self.round == 1:
                # 单帧带全部 tool_calls (chunk 相加语义下多帧会 id 去重丢调用)
                yield AIMessage(
                    content="",
                    tool_calls=[
                        {"name": "docker_restart", "args": {"container": "postgres-db"}, "id": "c1"},
                        {"name": "docker_restart", "args": {"container": "nginx-proxy"}, "id": "c2"},
                    ],
                )
            else:
                yield AIMessage(content="done")

    class _Tool:
        name = "docker_restart"

        async def ainvoke(self, args):  # noqa: ANN001
            calls.append(args)
            return "restarted"

    result = await run_parallel_agent(
        llm=_LLM(),
        tools=[_Tool()],
        system_prompt="s",
        inputs={"messages": [("user", "重启")]},
        max_iters=2,
        decisions={"docker_restart": evaluate_permission(
            "docker_restart", None, skill_allowed=ALLOWED, mode=PermissionMode.BYPASS
        )},
    )

    # 只有白名单内的 nginx-proxy 真的执行了
    assert calls == [{"container": "nginx-proxy"}]

    # 消息里能看到对 postgres-db 的拒绝回填 (LLM 可读原因)
    msgs = result["messages"]
    denies = [m for m in msgs if getattr(m, "type", "") == "tool" and "postgres-db" in str(getattr(m, "content", ""))]
    assert denies, "白名单外调用应回填拒绝消息"
