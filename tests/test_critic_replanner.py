"""app.agents.critic / app.agents.replanner 可测纯函数 + LLM mock 分支测试.

- critic_node: mock ainvoke_structured 返回通过/驳回/异常三分支
- replanner: _last_step_failed / _ensure_report_time / _force_summary 纯函数
- harness: 防复读机 (_has_repeated_steps / _fingerprint_step / evaluate_replanner_pre_llm)
"""

from __future__ import annotations

import pytest

import app.agents.critic as critic_mod
from app.agents.critic import CriticDecision, critic_node
from app.agents.replanner import (
    _ensure_report_time,
    _force_summary,
    _last_step_failed,
)
from app.runtime.agent_harness import get_agent_harness


# ============================================================
# Critic: mock LLM 结构化输出
# ============================================================
async def _critic_with_decision(monkeypatch, decision, *, raise_exc=None):
    async def fake_structured(**kwargs):
        if raise_exc is not None:
            raise raise_exc
        return decision

    # 同时 mock 客户端构造与结构化调用: 测试必须离线可跑, 不依赖任何 API key
    monkeypatch.setattr(critic_mod, "get_chat_llm", lambda **kwargs: object())
    monkeypatch.setattr(critic_mod, "ainvoke_structured", fake_structured)
    state = {
        "input": "q",
        "past_steps": [("查 CPU", "CPU 98%, iowait 高")],
    }
    return await critic_node(state)


async def test_critic_pass(monkeypatch):
    out = await _critic_with_decision(
        monkeypatch, CriticDecision(is_passed=True, feedback="OK")
    )
    assert out["critic_passed"] is True
    assert out["critic_feedback"] == ""
    assert out["transition_history"][0]["reason"] == "CRITIC_OK"


async def test_critic_reject(monkeypatch):
    out = await _critic_with_decision(
        monkeypatch,
        CriticDecision(is_passed=False, feedback="脚本第 3 行 NameError, 请修正"),
    )
    assert out["critic_passed"] is False
    assert "NameError" in out["critic_feedback"]
    assert out["transition_history"][0]["reason"] == "CRITIC_REJECTED"


async def test_critic_llm_failure_defaults_pass(monkeypatch):
    # LLM 异常时为不阻塞流程默认放行
    out = await _critic_with_decision(
        monkeypatch, None, raise_exc=RuntimeError("LLM down")
    )
    assert out["critic_passed"] is True
    assert out["critic_feedback"] == ""


async def test_critic_no_steps_passes_early(monkeypatch):
    # 没有任何 past_steps → 不调 LLM 直接通过
    called = {"n": 0}

    async def fail_if_called(**kwargs):
        called["n"] += 1
        raise AssertionError("should not call LLM")

    monkeypatch.setattr(critic_mod, "ainvoke_structured", fail_if_called)
    out = await critic_node({"input": "q", "past_steps": []})
    assert out["critic_passed"] is True
    assert called["n"] == 0


# ============================================================
# Replanner: 纯函数
# ============================================================
def test_last_step_failed_detection():
    assert _last_step_failed([("s", "[执行失败: TimeoutError]")] ) is True
    assert _last_step_failed([("s", "[超过最大步数]")]) is True
    assert _last_step_failed([("s", "CPU 使用率 98%")]) is False
    assert _last_step_failed([]) is False
    # 失败标记需出现在开头 (前 50 字符)
    assert _last_step_failed([("s", "正常输出 " * 20 + "[执行失败]")]) is False


def test_ensure_report_time_replaces_existing():
    report = "# 故障诊断报告\n**生成时间**: 2000-01-01\n\n正文"
    out = _ensure_report_time(report, "2026-08-27 10:00:00")
    assert "2026-08-27 10:00:00" in out
    assert "2000-01-01" not in out
    assert out.count("**生成时间**") == 1


def test_ensure_report_time_inserts_after_title():
    report = "# 故障诊断报告\n\n正文"
    out = _ensure_report_time(report, "2026-08-27 10:00:00")
    assert "**生成时间**: 2026-08-27 10:00:00" in out
    assert out.index("# 故障诊断报告") < out.index("**生成时间**")


def test_ensure_report_time_prepends_header_if_missing():
    out = _ensure_report_time("只是正文", "2026-08-27 10:00:00")
    assert out.startswith("# 故障诊断报告")


def test_force_summary_no_steps():
    out = _force_summary("数据库慢查询", [], "2026-08-27")
    assert "诊断流程异常终止" in out
    assert "数据库慢查询" in out


def test_force_summary_with_steps():
    steps = [("查 CPU", "98%"), ("查日志", "OOM killed")]
    out = _force_summary("input", steps, "2026-08-27")
    assert "查 CPU" in out and "查日志" in out
    assert "98%" in out
    assert "进一步人工确认" in out


# ============================================================
# Harness: 防复读机 / 快路径 / 强制收尾
# ============================================================
def test_fingerprint_step_normalization():
    h = get_agent_harness()
    a = h._fingerprint_step("Query CPU usage!")
    b = h._fingerprint_step("query cpu usage")
    assert a == b  # 忽略大小写与标点


def test_repeated_steps_detected():
    h = get_agent_harness()
    steps = [("查询 CPU 使用率", "r1"), ("查询 CPU 使用率!", "r2"), ("查询CPU使用率", "r3")]
    assert h._has_repeated_steps(steps) is True


def test_varied_steps_not_flagged():
    h = get_agent_harness()
    steps = [("查 CPU", "r1"), ("查内存", "r2"), ("查磁盘", "r3")]
    assert h._has_repeated_steps(steps) is False


def test_less_than_three_steps_never_repeat():
    h = get_agent_harness()
    assert h._has_repeated_steps([("same", "r1"), ("same", "r2")]) is False


def test_pre_llm_force_report_on_max_steps():
    h = get_agent_harness()
    d = h.evaluate_replanner_pre_llm({"iteration": 999, "plan": ["a"], "past_steps": []})
    assert d.action == "force_report"
    assert d.reason == "max_steps_reached"


def test_pre_llm_force_report_on_repeated_steps():
    h = get_agent_harness()
    state = {
        "iteration": 1,
        "plan": ["next"],
        "past_steps": [("查CPU", "r1"), ("查CPU!", "r2"), ("查CPU", "r3")],
    }
    d = h.evaluate_replanner_pre_llm(state)
    assert d.action == "force_report"
    assert d.reason == "repeated_steps_detected"


def test_pre_llm_fast_path_when_plan_remaining():
    h = get_agent_harness()
    state = {
        "iteration": 0,
        "plan": ["step1", "step2", "step3", "step4"],  # 剩余 3 >= 阈值 2
        "past_steps": [],
    }
    d = h.evaluate_replanner_pre_llm(state)
    assert d.action == "continue_fast_path"
    assert d.data["next_plan"] == ["step2", "step3", "step4"]


def test_pre_llm_fast_path_blocked_by_last_failure():
    h = get_agent_harness()
    state = {
        "iteration": 0,
        "plan": ["s1", "s2", "s3", "s4"],
        "past_steps": [("s1", "[执行失败: ConnectionError]")],
    }
    d = h.evaluate_replanner_pre_llm(state)
    assert d.action == "allow_llm"  # 上一步失败 → 不走快路径, 交给 Replanner LLM
