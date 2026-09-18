"""SecOps 域共享状态与结构化输出 Schema.

设计约定 (与 app/agents/state.py 对齐):
  - TypedDict total=False, LangGraph 标准模式
  - 普通字段覆盖, Annotated[List, operator.add] 累加
  - 所有 LLM 结构化输出用 Pydantic BaseModel, 走 ainvoke_structured

借鉴 SentinelOps 的三层状态 (evidence → context → fact_sheet) 并对齐项目纪律:
  verdict 四态 (benign/suspicious/malicious/inconclusive) 来自 OpenTriage 的
  Verdict 纪律 — 结论必须落到四态之一, 禁止「高危/低危」这种无判定语义的输出.
"""

import operator
from typing import Annotated, List, TypedDict

from pydantic import BaseModel, Field

# ============================================================
# 常量
# ============================================================
VERDICT_BENIGN = "benign"            # 误报 / 正常业务行为
VERDICT_SUSPICIOUS = "suspicious"    # 可疑, 建议持续观察或人工复核
VERDICT_MALICIOUS = "malicious"      # 恶意, 建议立即处置
VERDICT_INCONCLUSIVE = "inconclusive" # 证据不足, 无法判定

SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

# Analyst 置信度回环阈值 (借鉴 SentinelOps, 阈值放宽到 0.6/3 轮)
CONFIDENCE_THRESHOLD = 0.6
MAX_INVESTIGATION_LOOPS = 3

# 安全响应分级: 研判只产建议, 高风险动作必须人工审批 (硬编码, 不走 LLM)
RESPONSE_MODES = ("observe", "recommend", "human_approval")
# 哪些 severity 的建议动作必须带 human_approval (借鉴 AiSOC autonomy policy)
AUTO_SAFE_SEVERITIES = (SEVERITY_LOW,)


# ============================================================
# LangGraph 状态
# ============================================================
class SecOpsState(TypedDict, total=False):
    """SecOps 子图共享状态.

    字段说明:
        input:            原始安全告警文本 (不变)
        session_id:       会话 ID (SSE thread 关联)
        domain:           域分类结果: "security" | "ops" (统一入口写入)
        domain_confidence: 域分类置信度
        domain_reason:    域分类理由 (可观测)

        alert_type:       Triage 结构化分类 (brute_force/malware/...)
        severity:         初判严重度 LOW/MEDIUM/HIGH/CRITICAL
        key_indicators:   告警关键指标 (Triage 提取)
        triage_verdict:   Triage 初判: skip / investigate
        triage_reason:    Triage 初判理由

        iocs:             Scout 正则提取的 IOC (ips/hashes/domains/cves/urls)
        anomaly_score:    启发式异常分 0.0-1.0
        anomaly_reason:   异常模式一句话描述

        intel_snippets:   Enrich 威胁情报片段 (web_search provider)
        mitre_techniques: Enrich 映射的 MITRE ATT&CK 技术 ID 列表

        confidence:       Analyst 研判置信度 0.0-1.0
        assessment:       Analyst 威胁评估文本
        loop_count:       Scout→Analyst 调查回环次数 (防死循环)
        investigation_steps: 已执行调查步骤记录 (operator.add 累加)

        critic_passed:    Critic 是否放行
        critic_feedback:  Critic 驳回意见

        verdict:          最终四态判定 (benign/suspicious/malicious/inconclusive)
        response_mode:    响应模式 (observe/recommend/human_approval)
        response_actions: 建议处置动作列表 (纯建议, 执行必须人工审批)
        fact_sheet:       Reporter 生成的 Markdown 研判报告
        error:            异常信息 (fail-soft, 转报告不中断)
    """

    input: str
    session_id: str
    domain: str
    domain_confidence: float
    domain_reason: str

    alert_type: str
    severity: str
    key_indicators: List[str]
    triage_verdict: str
    triage_reason: str

    iocs: dict
    anomaly_score: float
    anomaly_reason: str

    intel_snippets: List[str]
    mitre_techniques: List[str]

    confidence: float
    assessment: str
    loop_count: int
    investigation_steps: Annotated[List[dict], operator.add]

    # 临时路由标记 (LangGraph 会丢弃 schema 外的键, 必须显式声明)
    investigation_pending: bool   # analyst 置 true 表示需回环补证据, graph 路由消费
    critic_retry_count: int       # critic 驳回后重回 analyst 的次数 (上限 1, 防死循环)

    # ===== 子代理调查 (决策/执行分离: Analyst 只看摘要) =====
    investigation_needs: str      # analyst 写: 还缺什么证据 (给调查子代理的目标)
    investigation_findings: Annotated[List[str], operator.add]  # 子代理返回的压缩发现

    critic_passed: bool
    critic_feedback: str

    verdict: str
    response_mode: str
    response_actions: List[str]
    fact_sheet: str
    error: str


# ============================================================
# 域分类器结构化输出 (统一入口)
# ============================================================
class DomainChoice(BaseModel):
    """统一事件入口的域分类结果."""

    domain: str = Field(
        ...,
        description=(
            "事件所属业务域: 'security' (安全告警研判) 或 'ops' (运维故障诊断). "
            "安全攻击/入侵/恶意软件/暴力破解/数据泄露/Web攻击/异常登录等 → security; "
            "服务宕机/性能/资源/网络不通/数据库/发布变更等 → ops."
        ),
    )
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="分类置信度")
    reason: str = Field(default="", description="一句话分类理由")


# ============================================================
# Triage 结构化输出
# ============================================================
class TriageDecision(BaseModel):
    """安全 Triage Agent 的结构化输出.

    借鉴 SentinelOps Supervisor 的分类字段 + OpenTriage 的 skip 纪律:
    明显误报 (如扫描器探测/健康检查触发 IDS) 应直接 skip, 不烧 token 调查.
    """

    alert_type: str = Field(
        ...,
        description=(
            "告警类型: brute_force | malware | network_scan | data_exfiltration | "
            "privilege_escalation | phishing | web_attack | anomaly | unknown"
        ),
    )
    severity: str = Field(
        ...,
        description="初判严重度: LOW | MEDIUM | HIGH | CRITICAL",
    )
    key_indicators: List[str] = Field(
        default_factory=list,
        description="告警中的关键指标 (IP/hash/域名/账号/行为特征)",
    )
    should_investigate: bool = Field(
        default=True,
        description=(
            "是否值得继续调查. 扫描器噪声/健康检查误报/已知白名单等明显误报设 false, "
            "直接出 benign 报告不烧 token (诚实止损纪律在安全域的对应物)."
        ),
    )
    reason: str = Field(default="", description="初判理由")


# ============================================================
# Analyst 结构化输出
# ============================================================
class AnalystAssessment(BaseModel):
    """安全 Analyst Agent 的结构化输出 (威胁研判核心)."""

    threat_assessment: str = Field(
        ...,
        description="2-3 句威胁评估: 正在发生什么, 攻击面在哪, 影响范围",
    )
    confidence: float = Field(
        default=0.5, ge=0.0, le=1.0,
        description=(
            "研判置信度 0.0-1.0. 指南: 0.0-0.3 证据极少疑似噪声; "
            "0.3-0.6 有部分证据但不充分; 0.6-0.8 证据较充分判定可信; "
            "0.8-1.0 证据链完整高度确信"
        ),
    )
    confidence_reason: str = Field(default="", description="置信度依据")
    mitre_techniques: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK 技术 ID 列表 (T1110/T1190 等, 需有证据支撑)",
    )
    needs_more_data: bool = Field(
        default=False,
        description="置信度不足时是否需要补充证据 (触发调查回环)",
    )
    investigation_needs: str = Field(
        default="",
        description=(
            "需要子代理定向调查的具体目标 (仅 needs_more_data=true 时填). "
            "写成可执行的调查指令, 如 'ping 1.2.3.4 并 http_check http://x 确认服务指纹' "
            "或 '检索 CVE-2023-XXXX 是否存在公开利用'. 决策者只下达目标, 不亲自查."
        ),
    )
    verdict: str = Field(
        ...,
        description="四态判定: benign | suspicious | malicious | inconclusive",
    )
    verdict_reason: str = Field(default="", description="判定依据")


# ============================================================
# Reporter 结构化输出
# ============================================================
class ResponseRecommendation(BaseModel):
    """处置建议条目 (纯建议, 执行必须人工审批)."""

    action: str = Field(..., description="处置动作一句话")
    rationale: str = Field(default="", description="为什么建议这个动作")
    requires_approval: bool = Field(
        default=True,
        description="是否需要人工审批后才可执行 (默认 true, 安全默认)",
    )


class FactSheet(BaseModel):
    """安全研判报告的结构化输出."""

    summary: str = Field(..., description="执行摘要 3-4 句")
    verdict: str = Field(..., description="四态判定: benign | suspicious | malicious | inconclusive")
    severity: str = Field(..., description="LOW | MEDIUM | HIGH | CRITICAL")
    mitre_techniques: List[str] = Field(default_factory=list, description="MITRE 技术 ID")
    attacker_entities: List[str] = Field(default_factory=list, description="攻击者实体 (IP/域名/账号)")
    victim_entities: List[str] = Field(default_factory=list, description="受害资产实体")
    evidence_refs: List[str] = Field(
        default_factory=list,
        description="证据引用列表 (每条结论必须能对应到某条证据, 防幻觉)",
    )
    response_actions: List[ResponseRecommendation] = Field(
        default_factory=list,
        description="处置建议 (observe/recommend/human_approval 分级)",
    )


# ============================================================
# Critic 结构化输出
# ============================================================
class SecCriticDecision(BaseModel):
    """安全 Critic 的结构化输出.

    与 app/agents/critic.py 的 CriticDecision 同构但独立 (安全域证据纪律更严):
    结论必须引用证据, verdict 四态必须与证据强度匹配.
    """

    is_passed: bool = Field(..., description="研判是否通过审计")
    feedback: str = Field(default="", description="驳回意见 (不过时必填)")
    evidence_gap: str = Field(
        default="",
        description="证据缺口描述 (通过时也可指出, 供报告诚实标注)",
    )
