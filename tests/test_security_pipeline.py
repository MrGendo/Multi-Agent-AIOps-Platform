"""SecOps 研判管线 (analyst/critic/reporter/graph) 离线单测.

全部 mock LLM 边界 (ainvoke_structured), 不碰真实 LLM/网络.
"""

from __future__ import annotations

import pytest

from app.security.analyst import analyst_node
from app.security.critic import sec_critic_node
from app.security.reporter import reporter_node, resolve_response_mode
from app.security.state import (
    AnalystAssessment,
    FactSheet,
    ResponseRecommendation,
    SecCriticDecision,
    SecOpsState,
)


def _base_state(**overrides) -> dict:
    state: dict = {
        "input": "SSH brute-force from 203.0.113.42 to 10.0.0.5, 10 failed logins",
        "alert_type": "brute_force",
        "severity": "HIGH",
        "key_indicators": ["203.0.113.42"],
        "triage_verdict": "investigate",
        "iocs": {
            "ips": ["203.0.113.42", "10.0.0.5"],
            "hashes": [],
            "domains": [],
            "cves": [],
            "urls": [],
        },
        "anomaly_score": 0.3,
        "anomaly_reason": "2 IP",
        "intel_snippets": ["[203.0.113.42] known attacker infrastructure (source: http://x)"],
        "mitre_techniques": ["T1110"],
        "loop_count": 0,
    }
    state.update(overrides)
    return state


# ============================================================
# analyst_node
# ============================================================
class TestAnalyst:
    async def test_normal_path(self, monkeypatch):
        decision = AnalystAssessment(
            threat_assessment="来自 203.0.113.42 的 SSH 暴力破解, 结合情报属已知攻击基础设施",
            confidence=0.85,
            confidence_reason="本地失败登录证据 + 外部情报交叉",
            mitre_techniques=["T1110"],
            needs_more_data=False,
            verdict="malicious",
            verdict_reason="暴力破解行为 + 情报命中",
        )

        async def fake_structured(**kwargs):
            return decision

        monkeypatch.setattr("app.security.analyst.ainvoke_structured", fake_structured)
        result = await analyst_node(_base_state())
        assert result["verdict"] == "malicious"
        assert result["confidence"] == 0.85
        assert result["investigation_pending"] is False
        assert "T1110" in result["mitre_techniques"]

    async def test_invalid_verdict_normalized(self, monkeypatch):
        decision = AnalystAssessment(
            threat_assessment="x", confidence=0.9, verdict="超级危险",
        )
        async def fake_structured(**kwargs):
            return decision

        monkeypatch.setattr("app.security.analyst.ainvoke_structured", fake_structured)
        result = await analyst_node(_base_state())
        assert result["verdict"] == "inconclusive"

    async def test_llm_failure_fallback(self, monkeypatch):
        async def boom(**kwargs):
            raise RuntimeError("LLM down")

        monkeypatch.setattr("app.security.analyst.ainvoke_structured", boom)
        state = _base_state(anomaly_score=0.5)
        result = await analyst_node(state)
        assert result["verdict"] == "inconclusive"
        assert result["confidence"] == pytest.approx(0.45)
        # LLM 故障 ≠ 证据不足: 不触发调查回环 (回环只会再超时烧 token)
        assert result["investigation_pending"] is False
        assert result["loop_count"] == 0

    async def test_mitre_merge_dedup(self, monkeypatch):
        decision = AnalystAssessment(
            threat_assessment="x", confidence=0.9, mitre_techniques=["T1110", "T1021"],
            verdict="suspicious",
        )

        async def fake_structured(**kwargs):
            return decision

        monkeypatch.setattr("app.security.analyst.ainvoke_structured", fake_structured)
        result = await analyst_node(_base_state())
        assert result["mitre_techniques"] == ["T1110", "T1021"]

    async def test_needs_more_data_requires_low_confidence(self, monkeypatch):
        # needs_more_data=true 但 confidence 0.9 → 不置 pending
        decision = AnalystAssessment(
            threat_assessment="x", confidence=0.9, needs_more_data=True, verdict="suspicious",
        )

        async def fake_structured(**kwargs):
            return decision

        monkeypatch.setattr("app.security.analyst.ainvoke_structured", fake_structured)
        result = await analyst_node(_base_state())
        assert result["investigation_pending"] is False


# ============================================================
# sec_critic_node
# ============================================================
class TestSecCritic:
    async def test_pass(self, monkeypatch):
        async def fake_structured(**kwargs):
            return SecCriticDecision(is_passed=True)

        monkeypatch.setattr("app.security.critic.ainvoke_structured", fake_structured)
        state = _base_state(assessment="评估", verdict="suspicious", confidence=0.7)
        result = await sec_critic_node(state)
        assert result["critic_passed"] is True

    async def test_reject_with_feedback(self, monkeypatch):
        async def fake_structured(**kwargs):
            return SecCriticDecision(is_passed=False, feedback="仅一个 IP 不能定罪 malicious")

        monkeypatch.setattr("app.security.critic.ainvoke_structured", fake_structured)
        state = _base_state(assessment="评估", verdict="malicious", confidence=0.6)
        result = await sec_critic_node(state)
        assert result["critic_passed"] is False
        assert "不能定罪" in result["critic_feedback"]

    async def test_llm_failure_fail_open(self, monkeypatch):
        async def boom(**kwargs):
            raise RuntimeError("LLM down")

        monkeypatch.setattr("app.security.critic.ainvoke_structured", boom)
        state = _base_state(assessment="评估", verdict="suspicious")
        result = await sec_critic_node(state)
        assert result["critic_passed"] is True  # fail-open

    async def test_no_assessment_passes(self):
        result = await sec_critic_node(_base_state())
        assert result["critic_passed"] is True


# ============================================================
# reporter_node
# ============================================================
class TestReporter:
    def test_response_mode_hard_rules(self):
        assert resolve_response_mode("LOW") == "observe"
        assert resolve_response_mode("MEDIUM") == "recommend"
        assert resolve_response_mode("HIGH") == "human_approval"
        assert resolve_response_mode("CRITICAL") == "human_approval"
        assert resolve_response_mode("") == "human_approval"  # 非法走最严档
        assert resolve_response_mode("whatever") == "human_approval"

    async def test_normal_report(self, monkeypatch):
        sheet = FactSheet(
            summary="SSH 暴力破解攻击",
            verdict="malicious",
            severity="HIGH",
            mitre_techniques=["T1110"],
            attacker_entities=["203.0.113.42"],
            victim_entities=["10.0.0.5"],
            evidence_refs=["失败登录 x10", "情报命中 203.0.113.42"],
            response_actions=[
                ResponseRecommendation(action="封禁攻击 IP", rationale="阻断攻击", requires_approval=True),
            ],
        )

        async def fake_structured(**kwargs):
            return sheet

        monkeypatch.setattr("app.security.reporter.ainvoke_structured", fake_structured)
        state = _base_state(verdict="malicious", confidence=0.85, assessment="评估")
        result = await reporter_node(state)
        assert result["verdict"] == "malicious"
        assert result["response_mode"] == "human_approval"
        assert "处置建议" in result["fact_sheet"]
        assert "需人工审批" in result["fact_sheet"]
        assert isinstance(result["response_actions"], list)
        assert all(isinstance(a, str) for a in result["response_actions"])

    async def test_reporter_cannot_override_verdict(self, monkeypatch):
        # Reporter LLM 想翻案成 benign, 但 state 里 Analyst 已判 malicious → 保持 malicious
        sheet = FactSheet(
            summary="x", verdict="benign", severity="LOW",
        )

        async def fake_structured(**kwargs):
            return sheet

        monkeypatch.setattr("app.security.reporter.ainvoke_structured", fake_structured)
        state = _base_state(verdict="malicious", severity="HIGH", assessment="评估")
        result = await reporter_node(state)
        assert result["verdict"] == "malicious"  # Analyst 产出优先
        assert result["response_mode"] == "human_approval"  # severity=HIGH 硬规则

    async def test_llm_failure_rule_template(self, monkeypatch):
        async def boom(**kwargs):
            raise RuntimeError("LLM down")

        monkeypatch.setattr("app.security.reporter.ainvoke_structured", boom)
        state = _base_state(verdict="suspicious", severity="MEDIUM", assessment="评估文本")
        result = await reporter_node(state)
        assert result["fact_sheet"]  # 规则模板兜底非空
        assert "规则模板" in result["fact_sheet"]
        assert result["response_mode"] == "recommend"
        assert "\n" in result["fact_sheet"]  # 换行不拍平


# ============================================================
# build_secops_graph 全链路
# ============================================================
class TestSecOpsGraph:
    async def test_skip_short_circuit(self, monkeypatch):
        """初筛拦截: triage skip → 直接 END, 不跑后续节点."""
        from app.security import graph as g

        async def fake_triage(state):
            return {
                "alert_type": "network_scan",
                "severity": "LOW",
                "key_indicators": [],
                "triage_verdict": "skip",
                "triage_reason": "健康检查误报",
                "verdict": "benign",
                "response_mode": "observe",
                "fact_sheet": "# 安全告警研判报告（初筛拦截）",
            }

        monkeypatch.setattr(g, "triage_node", fake_triage)
        # 后续节点若被调用会炸 (extract 对 skip 输入无 IOC 也不该跑)
        async def must_not_run(state):
            raise AssertionError("skip 路径不应执行 scout")

        monkeypatch.setattr(g, "scout_node", must_not_run)
        graph = g.build_secops_graph()
        result = await graph.ainvoke({"input": "nmap 扫描噪声"}, config={})
        assert result["verdict"] == "benign"
        assert "初筛拦截" in result["fact_sheet"]

    async def test_full_investigation_path(self, monkeypatch):
        """完整调查路径: triage→scout→analyst→critic pass→reporter."""
        from app.security import graph as g

        async def fake_triage(state):
            return {
                "alert_type": "brute_force",
                "severity": "HIGH",
                "key_indicators": ["203.0.113.42"],
                "triage_verdict": "investigate",
                "triage_reason": "暴力破解需调查",
            }

        async def fake_enrich(iocs, **kwargs):
            return ["[203.0.113.42] known bad (source: http://x)"]

        async def fake_analyst(state):
            return {
                "assessment": "暴力破解攻击",
                "confidence": 0.85,
                "verdict": "malicious",
                "verdict_reason": "证据充分",
                "mitre_techniques": ["T1110"],
                "investigation_pending": False,
                "loop_count": 1,
            }

        async def fake_critic(state):
            return {"critic_passed": True, "critic_feedback": ""}

        async def fake_reporter(state):
            return {
                "fact_sheet": "# 安全告警研判报告\n## 处置建议\n- 隔离资产",
                "verdict": "malicious",
                "severity": "HIGH",
                "response_mode": "human_approval",
                "response_actions": ["隔离资产 — 防横向移动"],
            }

        monkeypatch.setattr(g, "triage_node", fake_triage)
        monkeypatch.setattr(g, "enrich_iocs", fake_enrich)
        monkeypatch.setattr(g, "analyst_node", fake_analyst)
        monkeypatch.setattr(g, "sec_critic_node", fake_critic)
        monkeypatch.setattr(g, "reporter_node", fake_reporter)

        graph = g.build_secops_graph()
        result = await graph.ainvoke(
            {"input": "SSH brute-force from 203.0.113.42 to 10.0.0.5"}, config={}
        )
        assert result["verdict"] == "malicious"
        assert result["response_mode"] == "human_approval"
        assert "处置建议" in result["fact_sheet"]
        assert result["iocs"]["ips"] == ["203.0.113.42", "10.0.0.5"]
        assert result["intel_snippets"]
        assert "T1110" in result["mitre_techniques"]

    async def test_investigation_loop_converges(self, monkeypatch):
        """回环路径: 第一轮置信度不足回 scout, 第二轮收敛出报告."""
        from app.security import graph as g

        analyst_calls = {"n": 0}
        scout_calls = {"n": 0}

        async def fake_triage(state):
            return {"alert_type": "anomaly", "severity": "MEDIUM",
                    "key_indicators": [], "triage_verdict": "investigate",
                    "triage_reason": "异常需调查"}

        async def fake_scout(state):
            scout_calls["n"] += 1
            return {"iocs": {"ips": ["1.2.3.4"]}, "anomaly_score": 0.15,
                    "anomaly_reason": "1 IP", "intel_snippets": [],
                    "mitre_techniques": [], "investigation_steps": [{"loop": scout_calls["n"]}]}

        async def fake_analyst(state):
            analyst_calls["n"] += 1
            if analyst_calls["n"] == 1:
                return {"assessment": "证据不足", "confidence": 0.3, "verdict": "inconclusive",
                        "verdict_reason": "缺证据", "mitre_techniques": [],
                        "investigation_pending": True, "loop_count": 1}
            return {"assessment": "可疑行为", "confidence": 0.8, "verdict": "suspicious",
                    "verdict_reason": "二轮证据充分", "mitre_techniques": [],
                    "investigation_pending": False, "loop_count": 1}

        async def fake_critic(state):
            return {"critic_passed": True, "critic_feedback": ""}

        async def fake_reporter(state):
            return {"fact_sheet": "# 报告", "verdict": "suspicious", "severity": "MEDIUM",
                    "response_mode": "recommend", "response_actions": []}

        monkeypatch.setattr(g, "triage_node", fake_triage)
        monkeypatch.setattr(g, "scout_node", fake_scout)
        monkeypatch.setattr(g, "analyst_node", fake_analyst)
        monkeypatch.setattr(g, "sec_critic_node", fake_critic)
        monkeypatch.setattr(g, "reporter_node", fake_reporter)

        graph = g.build_secops_graph()
        result = await graph.ainvoke({"input": "异常流量 1.2.3.4"}, config={})
        assert scout_calls["n"] == 2  # 回环一次
        assert analyst_calls["n"] == 2
        assert result["verdict"] == "suspicious"

    async def test_critic_reject_retries_analyst_once(self, monkeypatch):
        """Critic 驳回 → analyst 重研判一次; 再驳回也必须进 reporter (不死循环)."""
        from app.security import graph as g

        analyst_calls = {"n": 0}

        async def fake_triage(state):
            return {"alert_type": "brute_force", "severity": "HIGH",
                    "key_indicators": [], "triage_verdict": "investigate",
                    "triage_reason": "x"}

        async def fake_scout(state):
            return {"iocs": {"ips": []}, "anomaly_score": 0.0, "anomaly_reason": "",
                    "intel_snippets": [], "mitre_techniques": [], "investigation_steps": []}

        async def fake_analyst(state):
            analyst_calls["n"] += 1
            return {"assessment": "评估", "confidence": 0.9, "verdict": "malicious",
                    "verdict_reason": "x", "mitre_techniques": [],
                    "investigation_pending": False, "loop_count": 0,
                    "critic_retry_count": analyst_calls["n"] - 1}

        critic_calls = {"n": 0}

        async def fake_critic(state):
            critic_calls["n"] += 1
            return {"critic_passed": False, "critic_feedback": "证据不足"}  # 永远驳回

        async def fake_reporter(state):
            return {"fact_sheet": "# 报告", "verdict": "malicious", "severity": "HIGH",
                    "response_mode": "human_approval", "response_actions": []}

        monkeypatch.setattr(g, "triage_node", fake_triage)
        monkeypatch.setattr(g, "scout_node", fake_scout)
        monkeypatch.setattr(g, "analyst_node", fake_analyst)
        monkeypatch.setattr(g, "sec_critic_node", fake_critic)
        monkeypatch.setattr(g, "reporter_node", fake_reporter)

        graph = g.build_secops_graph()
        result = await graph.ainvoke({"input": "攻击"}, config={})
        # analyst 跑 2 次 (原始 + 1 次重试), critic 跑 2 次, 然后强制进 reporter
        assert analyst_calls["n"] == 2
        assert critic_calls["n"] == 2
        assert result["fact_sheet"] == "# 报告"
