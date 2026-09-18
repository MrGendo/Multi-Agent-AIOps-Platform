"""SecOps 统一事件入口服务层.

把「安全告警研判」包装成与 aiops_service.stream_diagnose 同构的 SSE 事件流:
  统一域分类 (规则快路径 + LLM) → SecOps 子图 astream → 前端可消费事件

设计要点:
  - 与 AIOps 域共用事件总线形态 ({type, stage, message, data}), 前端零新概念
  - 域分类是入口第一跳: security 域走本模块 SecOps 子图, ops 域原样转投
    aiops_service.stream_diagnose (存量主路径不动)
  - 全程 fail-soft: 分类失败/子图异常都降级为 error 事件, 不让流中断
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, AsyncIterator, Dict

from loguru import logger

from app.agents.stream_sink import set_sink
from app.security.domain_classifier import classify_domain


def _make_event(
    event_type: str, stage: str, message: str = "", **data: Any
) -> Dict[str, Any]:
    """构造统一格式 SSE 事件 (与 aiops_service._make_event 同构)."""
    return {"type": event_type, "stage": stage, "message": message, "data": data}


async def stream_triage(
    query: str, *, session_id: str = "default"
) -> AsyncIterator[Dict[str, Any]]:
    """安全告警研判流式入口.

    Args:
        query:      安全告警文本 (攻击描述 / IDS 告警 / webhook 渲染文本)
        session_id: 会话 ID

    Yields:
        SSE 事件字典, 类型: start/domain_classified/triage/analyst/critic/
        report/complete/error
    """
    logger.info(f"[secops] session={session_id} | query={query[:100]}...")
    t0 = time.perf_counter()

    yield _make_event(
        "start", "triage_init", message="开始安全告警研判", query=query, session_id=session_id
    )

    # ===== 1. 统一域分类 (入口第一跳) =====
    domain_info: Dict[str, Any] = {}
    try:
        domain_info = await classify_domain(query)
    except Exception as exc:
        logger.exception(f"[secops] 域分类异常, 兜底运维域: {exc}")
        domain_info = {"domain": "ops", "confidence": 0.3, "reason": f"分类异常兜底: {exc}"}

    domain = domain_info.get("domain", "ops")
    yield _make_event(
        "domain_classified",
        "domain_classified",
        message=f"事件分类: {'安全域' if domain == 'security' else '运维域'} — {domain_info.get('reason', '')}",
        domain=domain,
        confidence=domain_info.get("confidence", 0.0),
        reason=domain_info.get("reason", ""),
    )

    # ===== 2. ops 域转投存量 AIOps 主路径 (完全复用, 不在本模块重复实现) =====
    if domain != "security":
        logger.info(f"[secops] session={session_id} | 转投 AIOps 运维域")
        import app.services.aiops_service as aiops_service

        async for ev in aiops_service.stream_diagnose(query, session_id=session_id):
            yield ev
        return

    # ===== 3. security 域: 跑 SecOps 子图 =====
    from app.security.graph import build_secops_graph

    graph = build_secops_graph()
    # scout_step 等图内事件经 stream_sink 旁路外送 (与 AIOps 域同机制):
    # set_sink 设进当前 context, graph.astream 的任务树自动复制继承
    token_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=256)
    set_sink(token_queue)

    try:
        final_state: Dict[str, Any] = {}

        yield_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=512)

        async def _run_graph() -> None:
            try:
                async for event in graph.astream(
                    {"input": query, "session_id": session_id},
                    config={"recursion_limit": 30},
                ):
                    for node_name, node_output in event.items():
                        if not isinstance(node_output, dict):
                            continue
                        final_state.update(node_output)
                        async for sse_event in _convert_secops_event(node_name, node_output):
                            await yield_queue.put(sse_event)
            except Exception as exc:
                await yield_queue.put({"__graph_error__": exc})
            finally:
                await token_queue.put({"__done__": True})
                await yield_queue.put({"__graph_end__": True})

        async def _pump_sink() -> None:
            """把 stream_sink 旁路事件 (scout_step) 转进统一队列."""
            while True:
                item = await token_queue.get()
                if item.get("__done__"):
                    return
                payload = {
                    k: v for k, v in item.items()
                    if k not in ("type", "message", "stage")
                }
                await yield_queue.put(
                    _make_event(
                        item.get("type", "scout_step"),
                        item.get("stage", "scout"),
                        message=item.get("message", ""),
                        **payload,
                    )
                )

        asyncio.create_task(_run_graph())
        pumper = asyncio.create_task(_pump_sink())
        graph_error: Exception | None = None
        while True:
            item = await yield_queue.get()
            if item.get("__graph_end__"):
                break
            if item.get("__graph_error__"):
                graph_error = item["__graph_error__"]
                continue
            yield item
        if not pumper.done():
            await asyncio.wait_for(pumper, timeout=2)
        if graph_error is not None:
            raise graph_error
    except Exception as exc:
        logger.exception(f"[secops] session={session_id} | 研判子图异常: {exc}")
        yield _make_event(
            "error",
            "triage_failed",
            message=f"安全研判失败: {type(exc).__name__}: {exc}",
            error_type=type(exc).__name__,
        )
        return

    # ===== 4. 收尾 =====
    fact_sheet = final_state.get("fact_sheet", "")
    verdict = final_state.get("verdict", "")
    severity = final_state.get("severity", "")
    confidence = float(final_state.get("confidence") or 0.0)
    elapsed_ms = int((time.perf_counter() - t0) * 1000)

    # 取证引导: 无法判定/低置信时, 按 alert_type 给「设备→操作→证据」清单
    guidance_md = ""
    dialogue_session_id = ""
    if fact_sheet:
        try:
            from app.security.followup import (
                build_followup_guidance,
                needs_guidance,
                render_guidance_markdown,
            )

            if needs_guidance(verdict, confidence):
                guidance = build_followup_guidance(
                    final_state.get("alert_type", ""),
                    final_state.get("iocs") or {},
                    reason=final_state.get("verdict_reason", ""),
                    confidence=confidence,
                )
                guidance_md = render_guidance_markdown(guidance)
        except Exception as exc:
            logger.warning(f"[secops] 取证引导生成失败 (忽略): {exc}")

        # 创建研判对话会话 (分析师可继续补充证据多轮研判)
        try:
            from app.security.dialogue import create_session

            dlg = create_session(
                alert_text=query,
                report=fact_sheet + guidance_md,
                verdict=verdict,
                severity=severity,
                response_mode=final_state.get("response_mode", ""),
                iocs=final_state.get("iocs") or {},
                alert_type=final_state.get("alert_type", ""),
                base_session_id=session_id,
            )
            dialogue_session_id = dlg.session_id
        except Exception as exc:
            logger.warning(f"[secops] 对话会话创建失败 (忽略): {exc}")

    # 研判经验异步沉淀 (与 AIOps 域 consolidation 对称; fail-soft 不阻塞)
    if fact_sheet:
        try:
            from app.security.consolidation import consolidate_triage_report

            asyncio.create_task(
                consolidate_triage_report(
                    session_id, query, fact_sheet, verdict
                )
            )
        except Exception as exc:
            logger.warning(f"[secops] 经验沉淀触发失败 (忽略): {exc}")

    # 取证引导作为独立事件 (前端在报告下方渲染)
    if guidance_md:
        yield _make_event(
            "followup_guidance",
            "needs_more_evidence",
            message="当前证据不足以确定判定, 已生成取证引导",
            guidance_md=guidance_md,
            needs_evidence=True,
        )

    yield _make_event(
        "complete",
        "triage_complete",
        message="安全研判流程完成",
        elapsed_ms=elapsed_ms,
        verdict=verdict,
        response_mode=final_state.get("response_mode", ""),
        report_len=len(fact_sheet),
        dialogue_session_id=dialogue_session_id,
        has_guidance=bool(guidance_md),
    )


async def _convert_secops_event(
    node_name: str, node_output: Dict[str, Any]
) -> AsyncIterator[Dict[str, Any]]:
    """SecOps 子图节点输出 → SSE 事件 (与 aiops_service._convert_node_event 同构)."""
    if node_name == "domain_classifier":
        yield _make_event(
            "domain_classified",
            "domain_classified",
            message=f"事件分类完成: {node_output.get('domain_reason', '')}",
            domain=node_output.get("domain", ""),
            confidence=node_output.get("domain_confidence", 0.0),
            reason=node_output.get("domain_confidence", ""),
        )

    elif node_name == "triage":
        verdict = node_output.get("triage_verdict", "")
        if verdict == "skip":
            yield _make_event(
                "report",
                "report_generated",
                message="初筛判定误报/噪声, 已拦截",
                report=node_output.get("fact_sheet", ""),
            )
        else:
            yield _make_event(
                "triage",
                "triage_classified",
                message=(
                    f"告警分类: {node_output.get('alert_type', 'unknown')} | "
                    f"初判严重度: {node_output.get('severity', 'MEDIUM')}"
                ),
                alert_type=node_output.get("alert_type", ""),
                severity=node_output.get("severity", ""),
                key_indicators=node_output.get("key_indicators", []),
                reason=node_output.get("triage_reason", ""),
            )

    elif node_name == "scout":
        iocs = node_output.get("iocs", {}) or {}
        ips = iocs.get("ips", [])
        hashes = iocs.get("hashes", [])
        cves = iocs.get("cves", [])
        yield _make_event(
            "scout",
            "evidence_gathered",
            message=(
                f"证据收集: {len(ips)} IP, {len(hashes)} hash, {len(cves)} CVE | "
                f"异常分 {node_output.get('anomaly_score', 0.0)}"
            ),
            iocs=iocs,
            anomaly_score=node_output.get("anomaly_score", 0.0),
            anomaly_reason=node_output.get("anomaly_reason", ""),
        )

    elif node_name == "analyst":
        yield _make_event(
            "analyst",
            "assessment_updated",
            message=(
                f"研判: {node_output.get('verdict', '')} | "
                f"置信度 {node_output.get('confidence', 0.0):.0%}"
            ),
            verdict=node_output.get("verdict", ""),
            confidence=node_output.get("confidence", 0.0),
            assessment=node_output.get("assessment", ""),
        )

    elif node_name == "investigator":
        # 调查子代理 (决策/执行分离): 只透出目标与压缩发现, 不透出原始工具日志
        findings = node_output.get("investigation_findings") or []
        objective = node_output.get("investigation_needs") or ""
        if findings or objective:
            yield _make_event(
                "investigator",
                "subagent_investigating",
                message="调查子代理执行定向调查",
                objective=objective,
                findings=findings,
            )

    elif node_name == "critic":
        passed = node_output.get("critic_passed", True)
        if passed:
            yield _make_event("critic", "critic_passed", message="研判审计通过")
        else:
            yield _make_event(
                "critic",
                "critic_rejected",
                message="研判审计驳回: 证据与结论不匹配",
                feedback=node_output.get("critic_feedback", ""),
            )

    elif node_name == "reporter":
        fact_sheet = node_output.get("fact_sheet", "")
        if fact_sheet:
            yield _make_event(
                "report",
                "report_generated",
                message="安全研判报告已生成",
                report=fact_sheet,
                verdict=node_output.get("verdict", ""),
                response_mode=node_output.get("response_mode", ""),
            )
