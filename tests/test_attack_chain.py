"""SecOps 攻击链路推演/漏洞通俗解读 (Reporter 扩展) 离线单测.

覆盖契约:
  ① FactSheet 带 attack_chain(3环节 SSRF 例)+vuln_explains(1条) →
     Markdown 含「## 攻击链路推演」「## 漏洞原理解读」且含环节文本, state 里 attack_chain 长度 3
  ② 空链空解读 → Markdown 不含这两个标题 (反幻觉: 整段不出)
  ③ LLM 抛异常 → 兜底报告仍生成, 两键为空列表 (兜底不编链)
  ④ service 层 _convert_secops_event reporter 输出 → 事件 data 透传两键

全部 mock LLM 边界 (ainvoke_structured), 不碰真实 LLM/网络.
"""

from __future__ import annotations

from app.security import graph as secops_graph
from app.security.reporter import reporter_node
from app.security.service import _convert_secops_event
from app.security.state import (
    AttackChainStep,
    FactSheet,
    VulnExplain,
)

# SSRF 三环节攻击链样例 (webhook 回调 → 内网请求 → 云元数据凭据)
_SSRF_CHAIN = [
    AttackChainStep(
        actor="攻击者 45.62.11.8",
        role="attacker",
        action="构造含内网地址的 URL 提交给 webhook 接口",
        evidence="WAF 日志: POST /webhook?url=http://169.254.169.254/latest/meta-data/",
        mitre="T1190",
    ),
    AttackChainStep(
        actor="订单服务 Web 服务器",
        role="pivot",
        action="服务端按攻击者指定地址发起请求 (SSRF 跳板)",
        evidence="出站连接: 10.0.2.15 → 169.254.169.254:80",
        mitre="",
    ),
    AttackChainStep(
        actor="云元数据服务 169.254.169.254",
        role="target",
        action="向已失陷的服务端进程返回实例临时凭据",
        evidence="响应体命中 IMDS 凭据特征 (ami-id/iam/security-credentials)",
        mitre="",
    ),
]

_SSRF_VULNS = [
    VulnExplain(
        vuln="SSRF (服务端请求伪造)",
        principle=(
            "服务器替用户去访问一个网址, 但没检查这个网址能不能去. "
            "攻击者把网址换成「内网内部地址」, 服务器就替他闯进了本不该外人进的内网, "
            "好比快递员被伪造的取件码指使去公司档案室翻文件."
        ),
        remediation=[
            "webhook 等回调地址走出网白名单 (仅允许可信域名)",
            "内网管理段 (含 169.254.169.254) 与业务服务网络隔离",
            "对用户提交的 URL 做协议与目标地址校验 (拒绝私网/环回/链路本地地址)",
        ],
    ),
]


def _base_state(**overrides) -> dict:
    """SSRF 告警基线 state (与 test_security_pipeline 同构)."""
    state: dict = {
        "input": (
            "WAF 告警: 外部 IP 45.62.11.8 向 /webhook 提交 "
            "url=http://169.254.169.254/latest/meta-data/ 触发 SSRF 规则"
        ),
        "alert_type": "web_attack",
        "severity": "HIGH",
        "key_indicators": ["45.62.11.8", "169.254.169.254"],
        "triage_verdict": "investigate",
        "iocs": {
            "ips": ["45.62.11.8", "169.254.169.254"],
            "hashes": [],
            "domains": [],
            "cves": [],
            "urls": ["http://169.254.169.254/latest/meta-data/"],
        },
        "anomaly_score": 0.6,
        "anomaly_reason": "外部 IP 提交内网链路本地地址",
        "intel_snippets": ["[45.62.11.8] 扫描/SSRF 利用源 (source: http://x)"],
        "mitre_techniques": ["T1190"],
        "loop_count": 1,
    }
    state.update(overrides)
    return state


def _ssrf_sheet() -> FactSheet:
    """带攻击链 + 漏洞解读的完整 FactSheet."""
    return FactSheet(
        summary="外部攻击者利用 webhook 接口 SSRF 探测云元数据服务",
        verdict="malicious",
        severity="HIGH",
        mitre_techniques=["T1190"],
        attacker_entities=["45.62.11.8"],
        victim_entities=["订单服务 Web 服务器"],
        evidence_refs=["WAF 日志: url=169.254.169.254", "出站连接 10.0.2.15→169.254.169.254"],
        attack_chain=_SSRF_CHAIN,
        vuln_explains=_SSRF_VULNS,
    )


# ============================================================
# ① 有链有解读: 渲染 + node 返回值
# ============================================================
async def test_attack_chain_and_vuln_explains_rendered(monkeypatch):
    """① FactSheet 带链 → Markdown 两段齐全含环节文本, 返回值 attack_chain 长度 3."""
    async def fake_structured(**kwargs):
        return _ssrf_sheet()

    monkeypatch.setattr("app.security.reporter.ainvoke_structured", fake_structured)
    state = _base_state(verdict="malicious", confidence=0.85, assessment="SSRF 利用")
    result = await reporter_node(state)

    md = result["fact_sheet"]
    # 两个新段落出现
    assert "## 攻击链路推演" in md
    assert "## 漏洞原理解读" in md
    # 环节文本 + 角色中文映射 (attacker/pivot/target)
    assert "45.62.11.8" in md
    assert "[攻击者]" in md
    assert "[跳板]" in md
    assert "[目标]" in md
    assert "云元数据服务 169.254.169.254" in md
    assert "T1190" in md
    assert "（证据:" in md
    # 漏洞解读内容
    assert "### SSRF (服务端请求伪造)" in md
    assert "**原理**:" in md
    assert "**通常修复**:" in md
    assert "白名单" in md
    # node 返回值 (进 state 的 dict 形态)
    assert len(result["attack_chain"]) == 3
    assert result["attack_chain"][0]["actor"] == "攻击者 45.62.11.8"
    assert result["attack_chain"][0]["role"] == "attacker"
    assert result["attack_chain"][2]["mitre"] == ""
    assert len(result["vuln_explains"]) == 1
    assert result["vuln_explains"][0]["vuln"] == "SSRF (服务端请求伪造)"
    assert isinstance(result["vuln_explains"][0]["remediation"], list)


async def test_full_graph_state_keeps_new_keys(monkeypatch):
    """① 全图跑通: LangGraph state 不丢 attack_chain/vuln_explains (schema 外键会被丢弃)."""
    async def fake_triage(state):
        return {
            "alert_type": "web_attack",
            "severity": "HIGH",
            "key_indicators": ["45.62.11.8"],
            "triage_verdict": "investigate",
            "triage_reason": "SSRF 利用需调查",
        }

    async def fake_enrich(iocs, **kwargs):
        return ["[45.62.11.8] known bad (source: http://x)"]

    async def fake_analyst(state):
        return {
            "assessment": "SSRF 攻击",
            "confidence": 0.9,
            "verdict": "malicious",
            "verdict_reason": "证据充分",
            "mitre_techniques": ["T1190"],
            "investigation_pending": False,
            "loop_count": 1,
        }

    async def fake_critic(state):
        return {"critic_passed": True, "critic_feedback": ""}

    async def fake_structured(**kwargs):
        return _ssrf_sheet()

    monkeypatch.setattr(secops_graph, "triage_node", fake_triage)
    monkeypatch.setattr(secops_graph, "enrich_iocs", fake_enrich)
    monkeypatch.setattr(secops_graph, "analyst_node", fake_analyst)
    monkeypatch.setattr(secops_graph, "sec_critic_node", fake_critic)
    # reporter_node 保持真实实现, 只 mock LLM 边界 (验证 model_dump 进 state 的完整链路)
    monkeypatch.setattr("app.security.reporter.ainvoke_structured", fake_structured)

    graph = secops_graph.build_secops_graph()
    result = await graph.ainvoke(
        {"input": "SSRF: 45.62.11.8 提交 url=http://169.254.169.254/ 至 webhook"},
        config={},
    )
    # state 键未被 LangGraph 丢弃
    assert len(result["attack_chain"]) == 3
    assert result["attack_chain"][0]["actor"] == "攻击者 45.62.11.8"
    assert len(result["vuln_explains"]) == 1
    assert "## 攻击链路推演" in result["fact_sheet"]
    assert "## 漏洞原理解读" in result["fact_sheet"]


# ============================================================
# ② 空链空解读: 反幻觉 — 整段不出
# ============================================================
async def test_empty_chain_renders_no_sections(monkeypatch):
    """② attack_chain/vuln_explains 为空 → Markdown 不出现两个新标题."""
    sheet = FactSheet(
        summary="普通暴力破解告警",
        verdict="suspicious",
        severity="MEDIUM",
        mitre_techniques=["T1110"],
        attacker_entities=["203.0.113.42"],
    )

    async def fake_structured(**kwargs):
        return sheet

    monkeypatch.setattr("app.security.reporter.ainvoke_structured", fake_structured)
    state = _base_state(verdict="suspicious", severity="MEDIUM", assessment="评估")
    result = await reporter_node(state)

    md = result["fact_sheet"]
    assert "## 攻击链路推演" not in md
    assert "## 漏洞原理解读" not in md
    assert "攻击链路推演" not in md  # 连内文都不应出现
    assert "漏洞原理解读" not in md
    # schema 默认值: 空列表而非 None
    assert result["attack_chain"] == []
    assert result["vuln_explains"] == []
    # 其余段落不受影响
    assert "## 处置建议" in md
    assert "## 执行摘要" in md


# ============================================================
# ③ LLM 失败: 兜底报告 + 两键空列表 (兜底不编链)
# ============================================================
async def test_llm_failure_fallback_keeps_empty_keys(monkeypatch):
    """③ ainvoke_structured 抛异常 → 规则模板兜底, attack_chain/vuln_explains 为空列表."""
    async def boom(**kwargs):
        raise RuntimeError("LLM down")

    monkeypatch.setattr("app.security.reporter.ainvoke_structured", boom)
    state = _base_state(verdict="suspicious", severity="MEDIUM", assessment="评估文本")
    result = await reporter_node(state)

    assert result["fact_sheet"]  # 兜底报告仍生成
    assert "规则模板" in result["fact_sheet"]
    assert "## 攻击链路推演" not in result["fact_sheet"]
    assert "## 漏洞原理解读" not in result["fact_sheet"]
    # 兜底不编链
    assert result["attack_chain"] == []
    assert result["vuln_explains"] == []
    assert result["error"].startswith("reporter_llm_failed")


# ============================================================
# ④ service 层事件透传
# ============================================================
async def test_service_report_event_passthrough():
    """④ reporter 节点输出 → report 事件 data 带攻击链/漏洞解读原样透传."""
    node_output = {
        "fact_sheet": "# 安全告警研判报告\n## 攻击链路推演\n1. **[攻击者] 攻击者 45.62.11.8** — x",
        "verdict": "malicious",
        "severity": "HIGH",
        "response_mode": "human_approval",
        "response_actions": ["隔离资产 — 防横向移动"],
        "attack_chain": [s.model_dump() for s in _SSRF_CHAIN],
        "vuln_explains": [v.model_dump() for v in _SSRF_VULNS],
    }

    events = [ev async for ev in _convert_secops_event("reporter", node_output)]
    assert len(events) == 1
    ev = events[0]
    assert ev["type"] == "report"
    data = ev["data"]
    assert len(data["attack_chain"]) == 3
    assert data["attack_chain"][0]["actor"] == "攻击者 45.62.11.8"
    assert data["attack_chain"][0]["mitre"] == "T1190"
    assert len(data["vuln_explains"]) == 1
    assert data["vuln_explains"][0]["vuln"] == "SSRF (服务端请求伪造)"
    assert data["verdict"] == "malicious"
    assert "攻击链路推演" in data["report"]


async def test_service_report_event_missing_keys_default_empty():
    """④ 旧节点输出缺两键 → 事件 data 兜底空列表 (不 None, 前端免判空)."""
    node_output = {
        "fact_sheet": "# 报告",
        "verdict": "benign",
        "response_mode": "observe",
    }
    events = [ev async for ev in _convert_secops_event("reporter", node_output)]
    assert len(events) == 1
    data = events[0]["data"]
    assert data["attack_chain"] == []
    assert data["vuln_explains"] == []


# ============================================================
# ⑤ 角色白名单归一 (LLM 自由文本角色 → attacker/pivot/target)
# ============================================================
async def test_role_normalization_free_text(monkeypatch):
    """⑤ role 返回「外部攻击者 (经受控服务端中转)」→ 归一 attacker, 白名单外归 pivot."""
    from app.security.reporter import _normalize_chain_role

    # 白名单原值直通
    assert _normalize_chain_role("attacker") == "attacker"
    assert _normalize_chain_role("Pivot") == "pivot"
    # 自由文本按关键词归一
    assert _normalize_chain_role("外部攻击者 (经受控服务端中转)") == "attacker"
    assert _normalize_chain_role("受害目标主机") == "target"
    assert _normalize_chain_role("跳板服务器") == "pivot"
    # 匹配不上 → pivot (中立方)
    assert _normalize_chain_role("mysterious") == "pivot"
    assert _normalize_chain_role("") == "pivot"


async def test_reporter_node_normalizes_roles(monkeypatch):
    """⑤ reporter_node 输出的 attack_chain 角色全部落在白名单内."""
    drifted = [
        AttackChainStep(
            actor="攻击者 1.2.3.4", role="外部攻击者",
            action="构造恶意 URL", evidence="WAF 日志", mitre="T1190",
        ),
        AttackChainStep(
            actor="云元数据服务", role="受害目标",
            action="返回临时凭据", evidence="响应体特征", mitre="",
        ),
    ]
    sheet = _ssrf_sheet().model_copy(update={"attack_chain": drifted})

    async def fake_structured(**kwargs):
        return sheet

    monkeypatch.setattr("app.security.reporter.ainvoke_structured", fake_structured)
    state = _base_state(verdict="malicious", confidence=0.85, assessment="SSRF")
    result = await reporter_node(state)
    roles = [s["role"] for s in result["attack_chain"]]
    assert roles == ["attacker", "target"], f"角色未归一: {roles}"
    # Markdown 渲染同样用归一后的角色
    assert "[攻击者]" in result["fact_sheet"]
    assert "[目标]" in result["fact_sheet"]
