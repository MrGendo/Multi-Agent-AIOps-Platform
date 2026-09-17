"""安全域入口模块测试: domain_classifier + triage.

全部离线: LLM 边界一律 mock (patch app.security.* 模块内的
get_chat_llm / ainvoke_structured), 返回真实 Pydantic schema 实例.
"""

from __future__ import annotations

import pytest

from app.security import domain_classifier as dc
from app.security import triage as tri
from app.security.domain_classifier import (
    classify_domain,
    classify_domain_rule,
    domain_classifier_node,
)
from app.security.state import DomainChoice, TriageDecision
from app.security.triage import triage_node


# ---------- helpers: LLM 边界 mock ----------


def _install_llm_mock(monkeypatch, choice_or_decision, calls):
    """patch 模块内 get_chat_llm + ainvoke_structured, 记录调用次数."""

    class _FakeLLM:
        pass

    async def fake_ainvoke(*, llm, schema_cls, messages, model_name):
        calls.append(schema_cls.__name__)
        if isinstance(choice_or_decision, Exception):
            raise choice_or_decision
        return choice_or_decision

    monkeypatch.setattr(dc, "get_chat_llm", lambda **kwargs: _FakeLLM())
    monkeypatch.setattr(dc, "ainvoke_structured", fake_ainvoke)
    monkeypatch.setattr(tri, "get_chat_llm", lambda **kwargs: _FakeLLM())
    monkeypatch.setattr(tri, "ainvoke_structured", fake_ainvoke)


# ---------- classify_domain_rule ----------


def test_rule_security_wins():
    text = "检测到 SQL 注入攻击, 疑似 sqli 漏洞利用, 攻击者持续探测"
    domain, reason = classify_domain_rule(text)
    assert domain == "security"
    assert reason


def test_rule_ops_wins():
    text = "订单服务大面积超时, CPU 水位 95%, 数据库连接池耗尽, 刚做完发布"
    domain, reason = classify_domain_rule(text)
    assert domain == "ops"
    assert reason


def test_rule_tie_goes_to_security():
    # 1 个安全词 (扫描) vs 1 个运维词 (超时) → 平局归 security 宁严勿漏
    text = "安全设备发出端口扫描超时告警"
    domain, _ = classify_domain_rule(text)
    assert domain == "security"


def test_rule_no_hit_returns_empty():
    domain, reason = classify_domain_rule("今天中午吃什么")
    assert domain == ""
    assert reason == "no keyword hit"


def test_rule_empty_text():
    domain, reason = classify_domain_rule("")
    assert domain == ""
    assert reason == "no keyword hit"


def test_rule_case_insensitive():
    domain, _ = classify_domain_rule("Brute Force attempt detected and DDoS traffic")
    assert domain == "security"


# ---------- classify_domain ----------


async def test_classify_fast_path_skips_llm(monkeypatch):
    calls: list[str] = []
    _install_llm_mock(monkeypatch, DomainChoice(domain="ops"), calls)

    result = await classify_domain("检测到暴力破解攻击, 疑似 brute force 失陷")

    assert result["domain"] == "security"
    assert result["confidence"] == 0.9
    assert "暴力破解" in result["reason"] or "安全" in result["reason"]
    assert calls == []  # 快路径不应触发 LLM


async def test_classify_llm_path(monkeypatch):
    calls: list[str] = []
    _install_llm_mock(
        monkeypatch,
        DomainChoice(domain="ops", confidence=0.7, reason="内存泄漏类故障"),
        calls,
    )

    result = await classify_domain("help, something broke weirdly here")

    assert result["domain"] == "ops"
    assert result["confidence"] == 0.7
    assert "内存泄漏" in result["reason"]
    assert calls == ["DomainChoice"]


async def test_classify_llm_failure_falls_back_to_ops(monkeypatch):
    calls: list[str] = []
    _install_llm_mock(monkeypatch, RuntimeError("llm down"), calls)

    result = await classify_domain("some ambiguous text no keyword")

    assert result == {
        "domain": "ops",
        "confidence": 0.3,
        "reason": "LLM 失败规则兑底默认运维域",
    }
    assert calls == ["DomainChoice"]


# ---------- domain_classifier_node ----------


async def test_node_idempotent_passthrough(monkeypatch):
    calls: list[str] = []
    _install_llm_mock(monkeypatch, DomainChoice(domain="security"), calls)

    state = {
        "input": "检测到暴力破解攻击",
        "domain": "ops",
        "domain_confidence": 0.85,
        "domain_reason": "上游已分类",
    }
    result = await domain_classifier_node(state)

    assert result["domain"] == "ops"
    assert result["domain_confidence"] == 0.85
    assert result["domain_reason"] == "上游已分类"
    assert calls == []  # 幂等: 不再分类


async def test_node_classifies_when_domain_missing(monkeypatch):
    calls: list[str] = []
    _install_llm_mock(monkeypatch, DomainChoice(domain="ops"), calls)

    result = await domain_classifier_node(dc.SecOpsState(input="检测到挖矿木马后门"))
    assert result["domain"] == "security"
    assert result["domain_confidence"] == 0.9
    assert calls == []


# ---------- triage_node: investigate 路径 ----------


async def test_triage_investigate_path(monkeypatch):
    calls: list[str] = []
    decision = TriageDecision(
        alert_type="brute_force",
        severity="HIGH",
        key_indicators=["10.0.0.5", "root"],
        should_investigate=True,
        reason="SSH 多次失败登录",
    )
    _install_llm_mock(monkeypatch, decision, calls)

    result = await triage_node({"input": "SSH 暴力破解告警 10.0.0.5"})

    assert result["triage_verdict"] == "investigate"
    assert result["should_investigate"] is True
    assert result["alert_type"] == "brute_force"
    assert result["severity"] == "HIGH"
    assert result["key_indicators"] == ["10.0.0.5", "root"]
    assert result["triage_reason"] == "SSH 多次失败登录"
    # investigate 路径不产 verdict/fact_sheet, 留给后续节点
    assert "verdict" not in result
    assert "fact_sheet" not in result
    assert calls == ["TriageDecision"]


async def test_triage_normalizes_invalid_values(monkeypatch):
    decision = TriageDecision(
        alert_type="port_probe",      # 非法 → unknown
        severity="extreme",           # 非法 → MEDIUM
        should_investigate=True,
        reason="x",
    )
    _install_llm_mock(monkeypatch, decision, [])

    result = await triage_node({"input": "whatever"})
    assert result["alert_type"] == "unknown"
    assert result["severity"] == "MEDIUM"
    assert result["triage_verdict"] == "investigate"


# ---------- triage_node: skip 路径 ----------


async def test_triage_skip_path_fills_fact_sheet(monkeypatch):
    decision = TriageDecision(
        alert_type="network_scan",
        severity="LOW",
        key_indicators=["10.1.2.3"],
        should_investigate=False,
        reason="监控探针端口探测, 已知白名单",
    )
    _install_llm_mock(monkeypatch, decision, [])

    alert_text = "IDS 告警: 内网监控探针 10.1.2.3 扫描了 443 端口"
    result = await triage_node({"input": alert_text})

    # skip 判定 + 后续节点可据此短路
    assert result["triage_verdict"] == "skip"
    assert result["should_investigate"] is False
    assert result["verdict"] == "benign"
    assert result["response_mode"] == "observe"
    # fact_sheet 已填: 标题 + 告警原文 + 初判理由 + 建议观察
    fs = result["fact_sheet"]
    assert "安全告警研判报告（初筛拦截）" in fs
    assert "10.1.2.3" in fs          # 告警原文
    assert "监控探针" in fs          # 初判理由
    assert "建议观察" in fs or "观察" in fs


# ---------- triage_node: LLM 失败兜底 ----------


async def test_triage_llm_failure_continues(monkeypatch):
    calls: list[str] = []
    _install_llm_mock(monkeypatch, RuntimeError("router down"), calls)

    result = await triage_node({"input": "疑似挖矿"})

    # fail-严: 宁可继续调查, 不放走攻击
    assert result["triage_verdict"] == "investigate"
    assert result["should_investigate"] is True
    assert result["alert_type"] == "unknown"
    assert result["severity"] == "MEDIUM"
    assert result["key_indicators"] == []
    assert result["triage_reason"] == "Triage LLM 失败，宁严勿漏继续调查"
    assert calls == ["TriageDecision"]
