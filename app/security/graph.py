"""SecOps 安全告警研判子图.

拓扑 (借鉴 SentinelOps Supervisor→Scout→Analyst→Reporter 管线 +
OpenTriage Solver-Critic 纪律, 按项目风格重写):

    [START]
       │
       ▼
    ┌──────────┐  skip/初筛拦截 → 直接出 benign 报告
    │  Triage  │──────────────────────────────► [END]
    └────┬─────┘
       │ investigate
       ▼
    ┌──────────┐  ◄── 置信度不足回环 (≤3 次)
    │  Scout   │──────────────┐
    └──────────┘              │
       ▲                     ▼
       │            ┌──────────┐   驳回回炉 (≤1 次)
       └───────────│ Analyst  │◄──────────┐
                    └────┬─────┘           │
                         ▼                 │
                    ┌──────────┐           │
                    │  Critic  │───────────┘
                    └────┬─────┘
                         │ 通过
                         ▼
                    ┌──────────┐
                    │ Reporter │──► [END]
                    └──────────┘

无 checkpointer (安全域一次性研判, 无需中断恢复 — 与 AIOps 域的
HITL interrupt 路径刻意隔离: 研判产出只到「建议+需人工审批」为止).
"""

from __future__ import annotations

from typing import Literal

from langgraph.graph import END, START, StateGraph

from app.agents.stream_sink import emit
from app.security.analyst import analyst_node
from app.security.critic import sec_critic_node
from app.security.ioc_extractor import compute_anomaly_score, extract_iocs
from app.security.reporter import reporter_node
from app.security.state import (
    CONFIDENCE_THRESHOLD,
    MAX_INVESTIGATION_LOOPS,
    SecOpsState,
)
from app.security.threat_intel import enrich_iocs, map_mitre
from app.security.triage import triage_node

# Critic 驳回后重回 Analyst 的最大次数 (防死循环)
MAX_CRITIC_RETRIES = 1

# 回环时追加到告警文本的调查方向提示 (供 Scout 深挖)
_LOOP_HINT = "\n[调查补充] 上一轮置信度不足，请围绕已有 IOC 关联行为深挖（历史行为/关联资产/同类告警）"


# ============================================================
# Scout 节点 (证据收集, 内联定义)
# ============================================================
async def scout_node(state: SecOpsState) -> dict:
    """证据收集: IOC 提取 + 异常评分 + 威胁情报富化 + MITRE 映射.

    回环时对告警文本追加调查提示, 让提取/富化聚焦补充方向.
    全部组件 fail-soft: 情报失败/网络不可用 → 空结果继续走.
    """
    loop_count = int(state.get("loop_count") or 0)
    text = state.get("input", "")
    if loop_count > 0:
        text = text + _LOOP_HINT

    iocs = extract_iocs(text)
    anomaly_score = compute_anomaly_score(iocs, text)

    # 情报富化 (fail-soft, 内部已捕获异常)
    intel_snippets = await enrich_iocs(iocs)

    # MITRE: alert_type 静态映射 + 告警文本中的技术 ID
    mitre = map_mitre(state.get("alert_type", "unknown"), text)

    anomaly_reason = (
        f"IOC 密度: {len(iocs.get('ips', []))} IP / {len(iocs.get('hashes', []))} hash / "
        f"{len(iocs.get('cves', []))} CVE / {len(iocs.get('domains', []))} 域名"
    )

    result = {
        "iocs": iocs,
        "anomaly_score": anomaly_score,
        "anomaly_reason": anomaly_reason,
        "intel_snippets": intel_snippets,
        "mitre_techniques": mitre,
        "investigation_steps": [{
            "loop": loop_count + 1,
            "iocs": {k: len(v) for k, v in iocs.items()},
            "anomaly_score": anomaly_score,
            "intel_count": len(intel_snippets),
            "mitre": mitre,
        }],
    }
    await emit({
        "type": "scout_step",
        "stage": "scout",
        "message": f"证据收集完成 (loop {loop_count + 1})",
        "iocs": {k: v for k, v in iocs.items()},
        "anomaly_score": anomaly_score,
    })
    return result


# ============================================================
# 路由函数
# ============================================================
def route_after_triage(state: SecOpsState) -> Literal["scout", "__end__"]:
    """初筛拦截 (skip) 或已有报告 → 短路结束."""
    if state.get("triage_verdict") == "skip" or state.get("fact_sheet"):
        return END  # type: ignore[return-value]
    return "scout"


def route_after_analyst(state: SecOpsState) -> Literal["scout", "critic"]:
    """置信度不足且需补证据且未超回环上限 → 回 Scout; 否则进 Critic."""
    if (
        state.get("investigation_pending")
        and float(state.get("confidence") or 0.0) < CONFIDENCE_THRESHOLD
        and int(state.get("loop_count") or 0) < MAX_INVESTIGATION_LOOPS
    ):
        return "scout"
    return "critic"


def route_after_critic(state: SecOpsState) -> Literal["analyst", "reporter"]:
    """驳回且未超重试上限 → 回 Analyst 重研判; 否则进 Reporter."""
    if (
        not state.get("critic_passed", True)
        and int(state.get("critic_retry_count") or 0) < MAX_CRITIC_RETRIES
    ):
        return "analyst"
    return "reporter"


# ============================================================
# 图构建
# ============================================================
def build_secops_graph():
    """构建 SecOps 研判子图 (无 checkpointer, 一次性研判)."""
    workflow = StateGraph(SecOpsState)

    workflow.add_node("triage", triage_node)
    workflow.add_node("scout", scout_node)
    workflow.add_node("analyst", analyst_node)
    workflow.add_node("critic", sec_critic_node)
    workflow.add_node("reporter", reporter_node)

    workflow.add_edge(START, "triage")
    workflow.add_conditional_edges(
        "triage",
        route_after_triage,
        {"scout": "scout", END: END},
    )
    workflow.add_edge("scout", "analyst")
    workflow.add_conditional_edges(
        "analyst",
        route_after_analyst,
        {"scout": "scout", "critic": "critic"},
    )
    workflow.add_conditional_edges(
        "critic",
        route_after_critic,
        {"analyst": "analyst", "reporter": "reporter"},
    )
    workflow.add_edge("reporter", END)

    return workflow.compile()
