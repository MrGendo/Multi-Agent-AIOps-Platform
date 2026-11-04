"""SecOps 安全告警研判接口 (流式 SSE).

POST /api/v1/secops/triage
  -> 接收 SecurityTriageRequest (session_id, query)
  -> 返回 SSE 事件流: start/domain_classified/triage/scout/analyst/critic/report/complete/error

与 /aiops/diagnose 同构, 前端复用同一 SSE 消费模式.
"""

import asyncio
import json
from pathlib import Path
from urllib.parse import urlparse
from typing import AsyncIterator

from fastapi import APIRouter
from loguru import logger
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from app.security.service import stream_triage
from app.security.sigma_forge import ForgeRequest

router = APIRouter(prefix="/secops", tags=["secops"])


class SecurityTriageRequest(BaseModel):
    """安全告警研判请求."""

    session_id: str = Field(default="default", description="会话 ID")
    query: str = Field(
        default="",
        description="安全告警内容 (攻击描述 / IDS 告警 / 异常行为描述)",
        max_length=4000,
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "session_id": "sec-001",
                "query": "检测到来自 203.0.113.42 的 SSH 暴力破解, 10 次失败登录, 目标主机 10.0.0.5",
            }
        }
    }


@router.post(
    "/triage",
    summary="安全告警智能研判 (流式)",
    description=(
        "基于 LangGraph 的安全告警研判流水线:\n\n"
        "**SSE 事件类型**:\n"
        "- `start` - 流程启动\n"
        "- `domain_classified` - 域分类结果 (security/ops)\n"
        "- `triage` - Triage 分类 (告警类型/严重度/是否继续调查)\n"
        "- `scout` - IOC 证据收集\n"
        "- `analyst` - 威胁研判 (verdict + 置信度)\n"
        "- `critic` - 审计结果\n"
        "- `report` - 最终研判报告 (Markdown)\n"
        "- `complete` - 流程结束\n"
        "- `error` - 异常\n\n"
        "研判产出永远是「建议 + 需人工审批」, 不会自动执行任何处置动作."
    ),
)
async def secops_triage(req: SecurityTriageRequest) -> EventSourceResponse:
    logger.info(f"[secops] session={req.session_id}, q={req.query[:60]}...")

    async def event_generator() -> AsyncIterator[dict]:
        try:
            async for sse_event in stream_triage(req.query, session_id=req.session_id):
                yield {
                    "event": "message",
                    "data": json.dumps(sse_event, ensure_ascii=False),
                }
        except Exception as e:
            logger.exception(f"[secops] stream 异常: {e}")
            yield {
                "event": "message",
                "data": json.dumps(
                    {
                        "type": "error",
                        "stage": "stream_failure",
                        "message": str(e),
                        "data": {"error_type": type(e).__name__},
                    },
                    ensure_ascii=False,
                ),
            }

    return EventSourceResponse(event_generator())


# ============================================================
# 研判多轮对话
# ============================================================
from fastapi import Request  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402

from app.security import dialogue as sec_dialogue  # noqa: E402


class DialogueRequest(BaseModel):
    """一轮对话请求."""

    message: str = Field(..., max_length=8000, description="分析师输入 (取证材料/追问/纠正)")


@router.post("/dialogue/{session_id}", summary="研判对话 — 追加一轮 (补充证据继续研判)")
async def secops_dialogue_turn(session_id: str, req: DialogueRequest) -> JSONResponse:
    session = sec_dialogue.get_session(session_id)
    if not session:
        return JSONResponse(status_code=404, content={"detail": f"研判会话不存在: {session_id}"})
    result = await sec_dialogue.dialogue_turn(session, req.message)
    return {
        "session_id": session_id,
        "turns": len(session.turns),
        **result,
    }


@router.get("/dialogue", summary="历史研判对话列表")
async def secops_dialogue_list(limit: int = 50):
    return {"items": sec_dialogue.list_sessions(limit)}


@router.get("/dialogue/{session_id}", summary="研判对话详情 (含完整对话记录)")
async def secops_dialogue_detail(session_id: str) -> JSONResponse:
    session = sec_dialogue.get_session(session_id)
    if not session:
        return JSONResponse(status_code=404, content={"detail": "会话不存在"})
    return session.to_dict()


@router.post("/dialogue/{session_id}/close", summary="结束研判对话 (证据沉淀为经验)")
async def secops_dialogue_close(session_id: str) -> JSONResponse:
    session = sec_dialogue.get_session(session_id)
    if not session:
        return JSONResponse(status_code=404, content={"detail": "会话不存在"})
    result = await sec_dialogue.close_session(session)
    return {"session_id": session_id, **result}


# ============================================================
# 图片证据 (取证截图 -> 视觉模型转写 -> 进研判)
# ============================================================
from pydantic import BaseModel as _BM, Field as _F  # noqa: E402

from app.security.image_evidence import (  # noqa: E402
    extract_image_evidence,
    validate_image_b64,
)
from app.security import dialogue as sec_dialogue_mod  # noqa: E402


class ImageEvidenceRequest(_BM):
    """图片证据请求."""

    image_b64: str = _F(..., min_length=32, description="图片 base64 (不含 data: 前缀)")
    mime: str = _F(default="image/png", description="MIME 类型: png/jpeg/gif/webp")
    note: str = _F(default="", max_length=500, description="分析师对图片的说明 (可选)")
    message: str = _F(default="", max_length=4000, description="随图附加的文字说明 (可选)")


@router.post("/dialogue/{session_id}/image", summary="研判对话 — 上传取证截图 (视觉提取后进研判)")
async def secops_dialogue_image(session_id: str, req: ImageEvidenceRequest) -> JSONResponse:
    session = sec_dialogue_mod.get_session(session_id)
    if not session:
        return JSONResponse(status_code=404, content={"detail": f"研判会话不存在: {session_id}"})
    ok, err = validate_image_b64(req.image_b64, req.mime)
    if not ok:
        return JSONResponse(status_code=422, content={"detail": err})

    extraction = await extract_image_evidence(req.image_b64, req.mime, req.note)
    if not extraction:
        return JSONResponse(status_code=503, content={
            "detail": "图片提取服务暂不可用, 请稍后重试或改用文字粘贴证据"})

    # 转写文本作为该轮用户输入进对话研判 (含图说明则前置)
    user_input = f"[图片证据{' — ' + req.note if req.note else ''}]\n{extraction}"
    if req.message:
        user_input = f"{req.message}\n\n{user_input}"
    result = await sec_dialogue_mod.dialogue_turn(session, user_input)
    return {
        "session_id": session_id,
        "extraction": extraction[:1200],
        **result,
    }


@router.post("/triage/image", summary="带图研判 — 告警文本 + 取证截图 直接研判 (SSE 流式)")
async def secops_triage_with_image(req: ImageEvidenceRequest):
    """图片先转写为文字证据, 拼进告警文本走标准研判流 (含五阶段 SSE)."""
    import json as _json
    import time as _time

    from sse_starlette.sse import EventSourceResponse

    ok, err = validate_image_b64(req.image_b64, req.mime)
    if not ok:
        return JSONResponse(status_code=422, content={"detail": err})
    extraction = await extract_image_evidence(req.image_b64, req.mime, req.note)
    if not extraction:
        return JSONResponse(status_code=503, content={
            "detail": "图片提取服务暂不可用, 请稍后重试或改用文字提交告警"})

    alert_text = (
        f"{req.message or '安全设备截图告警, 请研判'}\n\n"
        f"[截图证据{' — ' + req.note if req.note else ''}]\n{extraction}"
    )
    session_id = f"img-{int(_time.time())}"

    async def event_generator():
        from app.security.service import stream_triage

        async for ev in stream_triage(alert_text, session_id=session_id):
            yield {"event": "message", "data": _json.dumps(ev, ensure_ascii=False)}

    return EventSourceResponse(event_generator())


# ============================================================
# 对话式告警关联研判 (Correlation Chat)
# ============================================================
import time as _time_mod  # noqa: E402

from app.security import correlation as corr  # noqa: E402


class CorrelationRequest(BaseModel):
    """关联研判一轮请求."""

    cid: str = Field(default="", description="会话 id (空则服务端新建 corr-<ts>-<rand4>)")
    message: str = Field(..., min_length=1, max_length=8000, description="本条告警/观察输入")
    model: str = Field(
        default="",
        description="可选: 覆盖 LLM 模型名 (如 qwen-plus; 空=默认配置). 主要用于主模型限流时的降级验证/运维.",
    )


@router.post(
    "/correlation",
    summary="关联研判 — 开会话/追加一轮 (SSE 流式)",
    description=(
        "对话式告警关联研判: 每轮粘贴一条告警, 提取 IOC 后做关联分析 (ReAct 只读工具取证).\\n\\n"
        "**SSE 事件类型** (event=message, data 为 json):\\n"
        "- `corr_alert_added` - 本条输入已收录为告警 {cid, alert_index, raw, iocs}\\n"
        "- `corr_tool_call` - 工具调用透出 {cid, name, args, result}\\n"
        "- `corr_assistant` - 本轮关联研判答案 {cid, answer}\\n"
        "- `corr_error` - 错误 {cid, message}\\n\\n"
        "status=reported 的会话拒绝追加 (需开新会话)."
    ),
)
async def secops_correlation_turn(req: CorrelationRequest) -> EventSourceResponse:
    started = _time_mod.monotonic()
    cid = req.cid or ""

    async def event_generator() -> AsyncIterator[dict]:
        llm_calls = 0

        async def emit(event_type: str, data: dict) -> None:
            nonlocal llm_calls
            if event_type in ("corr_tool_call", "corr_assistant"):
                llm_calls += 1
            yield_queue.append({"event": "message", "data": json.dumps(
                {"type": event_type, **data, "llm_calls": llm_calls,
                 "elapsed_ms": int((_time_mod.monotonic() - started) * 1000)},
                ensure_ascii=False)})

        # emit 是 async callable(type, data) — correlation_turn 内部逐事件回调
        import asyncio

        yield_queue: list = []

        # 新会话: 第一次拿到真实 cid 时先发 corr_cid (前端需要立即持有会话 id)
        resolved_cid = {"v": ""}

        async def emit_and_track(event_type: str, data: dict) -> None:
            real_cid = data.get("cid") or ""
            if real_cid and not resolved_cid["v"]:
                resolved_cid["v"] = real_cid
                yield_queue.append({"event": "message", "data": json.dumps(
                    {"type": "corr_cid", "cid": real_cid}, ensure_ascii=False)})
            await emit(event_type, data)

        async def pump() -> None:
            await corr.correlation_turn(cid, req.message, emit=emit_and_track, model=req.model)

        task = asyncio.get_event_loop().create_task(pump())
        while not (task.done() and not yield_queue):
            while yield_queue:
                yield yield_queue.pop(0)
            await asyncio.sleep(0)
            if task.done() and not yield_queue:
                break
        if task.exception() is not None:  # noqa: F821 — task 已完成
            logger.exception(f"[secops] correlation 流异常: {task.exception()}")
            yield {"event": "message", "data": json.dumps(
                {"type": "corr_error", "cid": req.cid,
                 "message": f"correlation_turn 异常: {task.exception()}"},
                ensure_ascii=False)}
        elif task.exception() is None and task.done():
            # 正常收尾: 透出 complete 事件
            result = task.result() if not task.cancelled() else None
            yield {"event": "message", "data": json.dumps(
                {"type": "complete", "cid": req.cid or (result or {}).get("cid", ""),
                 "answer": result,
                 "elapsed_ms": int((_time_mod.monotonic() - started) * 1000)},
                ensure_ascii=False)}

    return EventSourceResponse(event_generator())


@router.get("/correlation", summary="关联会话列表")
async def secops_correlation_list(limit: int = 20):
    return {"items": corr.list_sessions(limit)}


@router.get("/correlation/{cid}", summary="关联会话详情 (含全部告警/对话/报告)")
async def secops_correlation_detail(cid: str) -> JSONResponse:
    session = corr.get_session(cid)
    if not session:
        return JSONResponse(status_code=404, content={"detail": f"关联会话不存在: {cid}"})
    return {
        "cid": session.cid,
        "created_at": session.created_at,
        "alerts": [
            {"index": i, "raw": a.raw, "source": a.source, "src_ip": a.src_ip,
             "ts": a.ts, "iocs": a.iocs}
            for i, a in enumerate(session.alerts)
        ],
        "turns": [
            {"role": t.role, "content": t.content, "tools_used": t.tools_used, "ts": t.ts}
            for t in session.turns
        ],
        "last_summary": session.last_summary,
        "status": session.status,
        "report": session.report,
        "disposition": session.disposition,
    }


class CorrelationReportBody(BaseModel):
    """关联报告生成请求 (可选 body)."""

    model: str = Field(default="", description="可选: 覆盖 LLM 模型名 (降级验证用)")


@router.post(
    "/correlation/{cid}/report",
    summary="关联研判 — 生成最终关联报告 (SSE 流式; accept: application/json 返回 JSON)",
    description=(
        "把会话内全部告警做攻击链关联总结, 出统一 incident 报告\\n"
        "(verdict/severity/attack_chain/correlations/mitre/key_evidence/response_actions/conclusion).\\n\\n"
        "**SSE 事件**: `corr_report` {cid, report} | `corr_error` {cid, message} | `complete`."
    ),
)
async def secops_correlation_report(cid: str, request: Request, req: CorrelationReportBody | None = None):
    import time as _t

    started = _t.monotonic()

    async def event_generator() -> AsyncIterator[dict]:
        async def emit(event_type: str, data: dict) -> None:
            pass  # 事件由返回值统一透出 (见下)

        report = await corr.generate_correlation_report(cid, emit=None, model=(req.model if req else ""))
        etype = "corr_error" if report.get("error") else "corr_report"
        yield {"event": "message", "data": json.dumps(
            {"type": etype, "cid": cid, ("report" if etype == "corr_report" else "message"):
             (report if etype == "corr_report" else report.get("message", "")),
             "elapsed_ms": int((_t.monotonic() - started) * 1000)},
            ensure_ascii=False)}
        yield {"event": "message", "data": json.dumps(
            {"type": "complete", "cid": cid,
             "elapsed_ms": int((_t.monotonic() - started) * 1000)},
            ensure_ascii=False)}

    if "application/json" in (request.headers.get("accept") or ""):
        report = await corr.generate_correlation_report(cid, emit=None, model=(req.model if req else ""))
        status = 404 if report.get("error") == "session_not_found" else 200
        return JSONResponse(status_code=status, content=report)
    return EventSourceResponse(event_generator())


# ============================================================
# 处置登记 (Disposition)
# ============================================================
class DispositionRequest(BaseModel):
    """处置登记请求."""

    action: str = Field(
        ...,
        description="处置动作: resolved (已处置) / false_positive (误报) / deferred (搁置)",
        pattern="^(resolved|false_positive|deferred)$",
    )
    note: str = Field(default="", max_length=2000, description="处置备注 (谁处理的/做了什么)")
    verdict: str = Field(default="", description="最终判定 (可选, 四态; 关联会话报告里带)")


# 注意 parents[3]: app/api/v1/secops.py → v1 → api → app → 仓库根
# (曾写成 parents[2], 处置记录静默落到 app/data/ — 与研判历史分家, 上下文反哺/校准全 join 不到)
_HISTORY_FILE = Path(__file__).resolve().parents[3] / "data" / "alert_history.jsonl"


def _append_disposition_history(record: dict) -> None:
    """处置登记落 alert_history.jsonl (disposition 字段)."""
    _HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with _HISTORY_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


@router.post(
    "/correlation/{cid}/disposition",
    summary="处置登记 (关联会话维度) — 写回会话并落 alert_history.jsonl",
    description="动作: resolved / false_positive / deferred. 写回 CorrelationSession.disposition.",
)
async def secops_correlation_disposition(cid: str, req: DispositionRequest) -> JSONResponse:
    """关联会话处置登记 (显式路由, 避免 /{session_id}/disposition 通配匹配不到两段路径)."""
    return await secops_disposition(cid, req)


@router.post(
    "/{session_id}/disposition",
    summary="处置登记 — 记录会话/告警的处置结论 (落 alert_history.jsonl)",
    description=(
        "三类动作: `resolved` (已处置) / `false_positive` (误报) / `deferred` (搁置).\\n\\n"
        "session_id 支持两种维度:\\n"
        "- 关联会话 cid (`corr-...`) → 写回 CorrelationSession.disposition 并落 history\\n"
        "- triage session id → 落 history (无会话上下文时也可直接登记)"
    ),
)
async def secops_disposition(session_id: str, req: DispositionRequest) -> JSONResponse:
    now_iso = _time_mod.strftime("%Y-%m-%dT%H:%M:%S", _time_mod.localtime())
    record: dict = {
        "kind": "disposition",
        "session_id": session_id,
        "disposition": {
            "action": req.action,
            "note": req.note,
            "verdict": req.verdict,
            "ts": now_iso,
        },
        "finished_at": now_iso,
    }

    # 关联会话: 写回会话文件 (corr- 前缀且会话存在时)
    if session_id.startswith("corr-"):
        session = corr.get_session(session_id)
        if session is None:
            return JSONResponse(status_code=404, content={
                "detail": f"关联会话不存在: {session_id}"})
        session.disposition = record["disposition"]
        corr.save_session(session)
        if session.report:
            record["report_verdict"] = session.report.get("verdict", "")
            record["severity"] = session.report.get("severity", "")

    try:
        _append_disposition_history(record)
    except Exception as exc:
        logger.error(f"[secops] 处置登记落盘失败 session={session_id}: {exc}")
        return JSONResponse(status_code=500, content={"detail": f"处置登记落盘失败: {exc}"})

    logger.info(
        f"[secops] 处置登记 session={session_id} action={req.action}"
    )
    return {"session_id": session_id, "disposition": record["disposition"], "recorded": True}


# ============================================================
# 历史研判记录管理 (防堆积): 统计 / 策略化清理 / 单条删除
# ============================================================
from app.security import history_mgmt  # noqa: E402


class HistoryPurgeRequest(BaseModel):
    """历史清理请求."""

    targets: list[str] = Field(
        default=["dialogue", "correlation"],
        description="要清理的存储类别: history / dialogue / correlation (多选)",
    )
    keep_days: int = Field(default=0, ge=0, le=3650, description="保留最近 N 天 (0=不限)")
    keep_last: int = Field(default=0, ge=0, le=100000, description="保留最近 N 条 (0=不限)")
    keep_disposition: bool = Field(
        default=True,
        description="history 类: 带 disposition (人工处置登记) 的行永不清理 (默认保护)",
    )


class ExperienceDeleteRequest(BaseModel):
    """研判经验删除请求 (经验库治理 — 经验此前只进不出, 无质量出口)."""

    confirm: bool = Field(default=False, description="必须显式 true (删除不可恢复)")
    content_contains: str = Field(
        default="",
        description="删除内容含该关键词的经验条目 (如 「RFC 保留段」清评测污染经验)",
    )
    all_experiences: bool = Field(default=False, description="删除全部经验 (慎用)")


@router.get("/history/stats", summary="历史存储统计 — 三类存储条数/体积/时间范围")
async def secops_history_stats():
    return history_mgmt.get_stats()


@router.post(
    "/experience/delete",
    summary="研判经验删除 — 经验库治理通道 (评测污染/低质经验的出口)",
    description=(
        "经验库此前只进不出, 单条低质经验会持续影响后续同类研判 "
        "(评测实证: RFC 保留段经验压制 payload 证据)。"
        "content_contains 按内容匹配删除 (如 「RFC 保留段」清评测污染经验); 删除不可恢复, confirm 必须 true。"
    ),
)
async def secops_experience_delete(req: ExperienceDeleteRequest):
    if not req.confirm:
        return JSONResponse(status_code=422, content={"detail": "confirm 必须 true — 删除不可恢复"})
    if not req.content_contains and not req.all_experiences:
        return JSONResponse(status_code=422, content={"detail": "content_contains / all_experiences 至少给一个"})
    from app.security.consolidation import delete_experiences

    deleted = delete_experiences(
        content_contains=req.content_contains, all_experiences=req.all_experiences
    )
    if deleted == -1:
        return JSONResponse(status_code=503, content={"detail": "Milvus 不可用或无底层客户端, 稍后重试"})
    return {"deleted": deleted}


@router.post(
    "/history/purge",
    summary="历史清理 — 按类别与保留策略清理 (防堆积)",
    description=(
        "targets 可多选 history/dialogue/correlation; keep_days/keep_last 组合使用 "
        "(双 0 + keep_disposition=true 时 history 只清无处置登记的行)."
        "清理不可恢复, 前端有二次确认."
    ),
)
async def secops_history_purge(req: HistoryPurgeRequest):
    valid = {"history", "dialogue", "correlation"}
    bad = [t for t in req.targets if t not in valid]
    if bad:
        return JSONResponse(status_code=422, content={"detail": f"未知类别: {bad}"})
    if not req.targets:
        return JSONResponse(status_code=422, content={"detail": "targets 不能为空"})
    return history_mgmt.purge(
        targets=req.targets,
        keep_days=req.keep_days,
        keep_last=req.keep_last,
        keep_disposition=req.keep_disposition,
    )


@router.delete("/dialogue/{session_id}", summary="删除单个研判对话会话")
async def secops_dialogue_delete(session_id: str):
    ok = sec_dialogue.delete_session(session_id)
    if not ok:
        return JSONResponse(status_code=404, content={"detail": f"会话不存在: {session_id}"})
    return {"deleted": session_id}


@router.delete("/correlation/{cid}", summary="删除单个关联研判会话")
async def secops_correlation_delete(cid: str):
    ok = corr.delete_session(cid)
    if not ok:
        return JSONResponse(status_code=404, content={"detail": f"会话不存在: {cid}"})
    return {"deleted": cid}


# ============================================================
# 传感器覆盖自监 (Coverage Watch) — 防御的防御
# ============================================================
from app.security.coverage_watch import coverage_report  # noqa: E402


@router.get(
    "/coverage",
    summary="传感器覆盖自监 — 资产该报没报即盲区 (疑似断流检测)",
    description=(
        "资产拓扑中被引用的传感器, 最近 window_min 分钟在研判历史里零事件 → 标记 silent.\n\n"
        "结论是「疑似」而非确诊 (断流/正常静默期/资产刚接入都会触发), 供人/定时器调用.\n\n"
        "无资产拓扑时返回 no_topology."
    ),
)
async def secops_coverage(window_min: int = 30):
    return coverage_report(window_min=window_min)


# ============================================================
# 钓鱼邮件分析 (Email Triage)
# ============================================================
class EmailTriageRequest(BaseModel):
    session_id: str = Field(default="email-default", description="会话 ID")
    raw_email: str = Field(
        default="",
        description="邮件原文 (.eml 源码或粘贴的正文/headers 摘录, 自动识别)",
        max_length=60000,
    )
    note: str = Field(default="", max_length=2000, description="分析师备注")


class EmailImageRequest(BaseModel):
    """邮件截图分析: 视觉转写后走同一邮件研判管线."""

    image_b64: str = Field(default="", description="截图 base64 (不含 data: 前缀)")
    mime: str = Field(default="image/png")
    note: str = Field(default="", max_length=2000, description="分析师备注")


_EMAIL_EXTRACT_PROMPT = """你是邮件安全取证分析员。分析师上传了一封可疑邮件的截图 (网页邮箱截图 / 客户端截图 / .eml 文本截图)。

请把截图完整转写为邮件分析可用的文字, 要求:
1. 先转写所有可见的邮件头: 发件人 (From, 含显示名与实际地址)、收件人、回复地址 (Reply-To)、主题、日期 — 原样抄录, 看不清标注 [不可辨认]
2. 再完整转写正文内容 (含称呼、正文、署名)
3. 转写所有可见的链接 URL 与附件名 (哪怕在按钮文字里, 把按钮背后的链接写出来; 只见按钮文字没见 URL 就标注 [按钮: xxx, 链接不可见])
4. 不要推测补全, 不要给结论 — 只做忠实转写
直接输出转写文本, 不要寒暄。"""


_email_bg_tasks: set = set()   # 后台沉淀任务引用池 (防 GC 回收)


def email_history_domain(parsed: dict) -> str:
    """从解析结果取发件域 (历史统计键)."""
    from_addr = (parsed.get("headers") or {}).get("From", "")
    return from_addr.rsplit("@", 1)[-1].strip().strip(">").lower() if "@" in from_addr else ""


def _format_sender_history(parsed: dict) -> str:
    """同发件域历史判定 → 注入文本 (无记录返回空, 保持与旧管线一致)."""
    from app.security import email_history

    domain = email_history_domain(parsed)
    if not domain:
        return ""
    stats = email_history.sender_domain_stats(domain, days=90)
    if stats["total"] == 0:
        return ""
    by_cls = ", ".join(f"{k}×{v}" for k, v in stats["by_classification"].items())
    return (
        f"发件域 {domain} 近 90 天已有 {stats['total']} 次研判记录 ({by_cls}), "
        f"最近一次 {stats['last_ts']}"
        + (f" 判为 {stats['last_phishing_type']}" if stats.get("last_phishing_type") else "")
    )


async def _recall_email_experience(raw_email: str) -> str:
    """向量召回同类邮件研判经验 → 参考文本 (无命中/失败返回空)."""
    try:
        from app.core.vector_store import safe_similarity_search
        from app.security.consolidation import EMAIL_EXP_SOURCE

        docs = safe_similarity_search(
            f"钓鱼邮件研判 {raw_email[:500]}",
            k=2, filter=f'source == "{EMAIL_EXP_SOURCE}"',
        )
        return "\n---\n".join(
            (d.page_content or "")[:400] for d in (docs or [])
        ) or ""
    except Exception as exc:
        logger.debug(f"[EmailTriage] 经验召回失败 (fail-soft 跳过): {exc}")
        return ""


async def _run_email_triage_sse(raw_email: str, note: str, session_id: str):
    """邮件分析 SSE 流: start → parsing → analyzing → report → complete."""
    from app.security.email_triage import analyze_email, deterministic_signals, parse_email

    # data 必须显式 json.dumps — 不经序列化的 dict 会被 SSE 库按 Python repr 输出
    # (单引号), 前端 JSON.parse 直接失败; 与本文件其他 SSE 接口的序列化纪律一致
    async def _ev(etype: str, stage: str, message: str, **payload):
        return {"event": etype, "data": json.dumps({"stage": stage, "message": message, **payload}, ensure_ascii=False)}

    # 链接沙箱验证启用条件: 配了 urlscan key 且提取到 URL
    from app.security.link_verifier import sandbox_key

    auto_verify = bool(sandbox_key())

    yield await _ev("start", "start", "邮件分析启动")
    sandbox_task = None   # try 前初始化 — finally 任何路径下可安全引用
    try:
        # 阶段 1: 确定性解析 (毫秒级, 先给用户信号)
        parsed = parse_email(raw_email)
        signals = deterministic_signals(parsed)
        yield await _ev(
            "parsing", "parsing",
            f"解析完成: {len(parsed['headers'])} 个 header · {len(parsed['urls'])} 条链接 · "
            f"{len(parsed['attachments'])} 个附件 · 确定性信号 {len(signals)} 条",
            headers=parsed["headers"],
            urls=parsed["urls"],
            attachments=parsed["attachments"],
            signals=signals,
            auto_verify=auto_verify and bool(parsed["urls"]),
        )

        # 阶段 2 (可选): 链接沙箱验证 — 先取证后研判 (与 SecOps 流水同哲学):
        # 解析完立即并行提交沙箱 (submit 秒级), LLM 研判前等一个窗口收证据
        if auto_verify and parsed["urls"]:
            from app.security.link_verifier import verify_urls_bounded

            sandbox_task = asyncio.create_task(verify_urls_bounded(parsed["urls"]))
            yield await _ev(
                "verifying", "verifying",
                "沙箱验证中 (urlscan 代访, 本机零接触, 最多 3 条, 等待窗 ≤75s)…",
            )

        # 阶段 3: LLM 语义研判 — 沙箱证据/同域历史/同类经验 (若有) 注入上下文
        sandbox_verdicts: list = []
        sandbox_cancelled: list = []
        sandbox_evidence = ""
        if sandbox_task:
            from app.security.link_verifier import format_sandbox_evidence

            sandbox_verdicts, sandbox_cancelled = await sandbox_task
            sandbox_evidence = format_sandbox_evidence(sandbox_verdicts)
            verified_n = sum(1 for v in sandbox_verdicts if v.get("status") == "verified")
            yield await _ev(
                "analyzing", "analyzing",
                f"语义研判中 (发件人身份/话术/意图{' + 沙箱落地页证据' if sandbox_evidence else ''})…",
                sandbox_verified=verified_n,
            )
        else:
            yield await _ev("analyzing", "analyzing", "语义研判中 (发件人身份/话术/意图)…")

        # 同发件域历史判定 (毫秒级 jsonl 尾读) + 同类经验向量召回 — 均为可选注入
        history_context = _format_sender_history(parsed)
        experience_context = await _recall_email_experience(raw_email)

        result = await analyze_email(
            raw_email, note=note, sandbox_evidence=sandbox_evidence,
            history_context=history_context, experience_context=experience_context,
        )
        # 沙箱结论随报告一并交付 (前端信号卡 + 验证卡数据源)
        result["sandbox_link_verdicts"] = sandbox_verdicts

        # 历史落盘 (append-only, fail-soft) — 整理起来的基础
        from app.security import email_history

        email_history.append(
            classification=result["classification"],
            phishing_type=result.get("phishing_type", ""),
            confidence=result.get("confidence", 0.0),
            sender_domain=email_history_domain(parsed),
            from_header=parsed["headers"].get("From", ""),
            subject=parsed["headers"].get("Subject", ""),
            url_domains=[urlparse(u).hostname or "" for u in parsed["urls"][:5]],
            degraded=result.get("status") == "degraded",
        )

        yield await _ev(
            "report", "report",
            f"研判完成: {result['classification']} ({result['confidence']:.0%})"
            + (f" · 沙箱验证 {sum(1 for v in sandbox_verdicts if v.get('status') == 'verified')} 条" if sandbox_task else "")
            + (" · 同域历史: " + history_context if history_context else ""),
            result=result,
        )

        # 等待窗外被取消的 URL — 后补告知 (标注未参与研判)
        if sandbox_cancelled:
            yield await _ev(
                "link_report", "link_report",
                f"{len(sandbox_cancelled)} 条链接沙箱超时 (未参与本次研判): "
                + ", ".join(sandbox_cancelled[:3]),
                link_verdicts=[{
                    "url": u, "status": "skipped", "malicious": None, "score": None,
                    "categories": [], "final_url": None, "domain_age_days": None,
                    "screenshot": None, "error": "等待窗超时被取消, 未参与本次研判",
                } for u in sandbox_cancelled],
            )

        yield await _ev("complete", "complete", "邮件分析完成", session_id=session_id)

        # 钓鱼判定推送 (飞书/企微/邮件, 全 fail-soft) — 邮件管线是无人值守路径
        from app.core.notifier import notify_email, should_notify_email

        if should_notify_email(result["classification"], result.get("status") == "degraded"):
            _t = asyncio.create_task(notify_email(
                classification=result["classification"],
                confidence=result.get("confidence", 0.0),
                phishing_type=result.get("phishing_type", ""),
                intent=result.get("intent_summary", ""),
                sender=parsed["headers"].get("From", ""),
                subject=parsed["headers"].get("Subject", ""),
            ))
            _email_bg_tasks.add(_t)
            _t.add_done_callback(_email_bg_tasks.discard)

        # 经验提炼 (fire-and-forget): phishing 且非 degraded 才值得沉淀 —
        # 断连后仍应完成 (不进 finally 取消链), 失败 fail-soft 由函数自身兜住
        if result["classification"] == "phishing" and result.get("status") != "degraded":
            from app.security.consolidation import consolidate_email_verdict

            headers_brief = "\n".join(
                f"{k}: {v[:120]}" for k, v in (parsed["headers"] or {}).items()
            )
            summary = (
                f"判定: {result['classification']} ({result.get('phishing_type', 'none')}, "
                f"置信 {result.get('confidence', 0):.0%})\n意图: {result.get('intent_summary', '')}\n"
                f"关键依据: " + "; ".join(
                    i.get("description", "")[:60] for i in (result.get("indicators") or [])[:4]
                )
            )
            # 裸 create_task 无引用会被 GC 中途回收 (asyncio 已知坑) —
            # 模块级集合持有引用, 完成后自摘除
            _task = asyncio.create_task(consolidate_email_verdict(
                f"{headers_brief}\n\n{(parsed.get('body') or '')[:2000]}", summary
            ))
            _email_bg_tasks.add(_task)
            _task.add_done_callback(_email_bg_tasks.discard)
    except Exception as exc:
        logger.exception(f"[secops] 邮件分析异常 session={session_id}: {exc}")
        yield await _ev(
            "error", "error",
            f"邮件分析失败: {type(exc).__name__}: {exc}",
        )
    finally:
        # 客户端断连 (CancelledError 不进上面的 except) 也必须收回沙箱任务 —
        # 否则后台继续轮询 urlscan 与视觉 LLM, 白烧额度 (review 实测复现)
        if sandbox_task is not None:
            sandbox_task.cancel()


@router.post(
    "/email/triage",
    summary="钓鱼邮件分析 — 垃圾/恶意双维度判定 + 判断依据 + 安全验证剧本",
    description=(
        "粘贴 .eml 源码或邮件摘录 (headers+正文), 输出:\n\n"
        "- classification 四态: **phishing**(恶意攻击) / **spam**(垃圾骚扰) / suspicious / benign\n"
        "- phishing_type 细分: 凭据钓鱼/恶意附件投毒/BEC 冒充诈骗/勒索恐吓/中奖诈骗\n"
        "- indicators: 每条判断依据带原文证据 (发件人伪造/链接欺骗/紧迫话术/危险附件…)\n\n"
        "确定性解析先行 (header 伪造/URL 欺骗模式/危险附件类型 — 代码层验证), LLM 只做语义层; "
        "邮件原文 untrusted 包裹防注入。SSE 事件: start→parsing→analyzing→report→complete."
    ),
)
async def secops_email_triage(req: EmailTriageRequest):
    return EventSourceResponse(_run_email_triage_sse(req.raw_email, req.note, req.session_id))


@router.get(
    "/email/history",
    summary="钓鱼邮件研判历史 — 最近 N 条记录 (新→旧)",
    description="每次研判自动落盘; 记录含发件域/判定/细分类型/置信度/链接域。研判时同域历史自动注入上下文。",
)
async def secops_email_history(limit: int = 20):
    from app.security import email_history

    return {"records": email_history.query(limit=max(1, min(limit, 200)))}


@router.post(
    "/email/triage/image",
    summary="钓鱼邮件分析 (截图入口) — 视觉转写邮件内容后走同一研判管线",
    description=(
        "上传邮件截图 (网页邮箱/客户端截图), 视觉模型先忠实转写 (发件人/主题/正文/链接/附件名), "
        "转写文本再走 /email/triage 同一管线。适合只有截图、拿不到原文的场景。"
    ),
)
async def secops_email_triage_image(req: EmailImageRequest):
    from app.security.image_evidence import validate_image_b64

    async def _gen():
        yield {"event": "start", "data": json.dumps({"stage": "start", "message": "邮件截图分析启动"}, ensure_ascii=False)}
        ok, err = validate_image_b64(req.image_b64, req.mime)
        if not ok:
            yield {"event": "error", "data": json.dumps({"stage": "error", "message": f"图片校验失败: {err}"}, ensure_ascii=False)}
            return
        yield {"event": "transcribing", "data": json.dumps({"stage": "transcribing", "message": "视觉模型转写邮件截图中…"}, ensure_ascii=False)}
        transcript = await _extract_email_image(req.image_b64, req.mime, req.note)
        if not transcript:
            yield {"event": "error", "data": json.dumps({"stage": "error", "message": "截图转写失败 (视觉模型不可用或图片无法辨认)"}, ensure_ascii=False)}
            return
        yield {
            "event": "transcript",
            "data": json.dumps({
                "stage": "transcript",
                "message": f"转写完成 ({len(transcript)} 字)",
                "transcript": transcript,
            }, ensure_ascii=False),
        }
        # 转写文本走同一研判管线
        async for ev in _run_email_triage_sse(transcript, req.note, f"email-img-{int(_time_mod.time())}"):
            yield ev

    return EventSourceResponse(_gen())


async def _extract_email_image(image_b64: str, mime: str, note: str) -> str:
    """截图 → 邮件文本转写 (专用 prompt, 与 image_evidence 同机制)."""
    try:
        from langchain_core.messages import HumanMessage

        # 延迟导入避免模块级循环依赖 (与 email_triage.py 同来源)
        from app.core.llm import get_chat_llm
        from app.runtime.agent_harness import get_agent_harness

        harness = get_agent_harness()
        model = harness.router_model()
        llm = get_chat_llm(model=model, temperature=0, timeout=120, max_retries=2)
        note_line = f"\n(分析师备注: {note})" if note else ""
        msg = HumanMessage(content=[
            {"type": "text", "text": _EMAIL_EXTRACT_PROMPT + note_line},
            {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{image_b64}"}},
        ])
        resp = await llm.ainvoke([msg])
        content = getattr(resp, "content", resp)
        if isinstance(content, list):
            text = "".join(
                item.get("text", "") for item in content
                if isinstance(item, dict) and item.get("type") == "text"
            )
        else:
            text = str(content)
        logger.info(f"[EmailTriage] 截图转写完成 ({len(text)} 字)")
        return text.strip()
    except Exception as exc:
        logger.warning(f"[EmailTriage] 截图转写失败 (fail-soft): {exc}")
        return ""


# ============================================================
# 置信度校准 (Confidence Calibration) — 纯只读
# ============================================================
@router.get(
    "/calibration",
    summary="置信度校准报告 — 用人工处置真值验证自评置信度",
    description=(
        "把研判时 Analyst 自评置信度与人工处置登记 (resolved=真威胁 / "
        "false_positive=误报) join, 产出: 分桶 reliability 表 / ECE / Brier "
        "score / verdict×disposition 一致性矩阵.\n\n"
        "纯只读离线计算, 无配对样本时返回 insufficient_data."
    ),
)
async def secops_calibration():
    from app.security.calibration import calibration_report

    return calibration_report()


# ============================================================
# 检测规则反哺 (Detection Feedback Loop) — 研判经验 → Sigma 草稿
# ============================================================
class DetectionApproveRequest(BaseModel):
    reviewer: str = Field(default="", max_length=100, description="审批人")
    note: str = Field(default="", max_length=500, description="审批备注")


@router.post(
    "/detection/forge",
    summary="研判经验 → Sigma 检测规则草稿 (draft 状态, 不下发设备)",
    description=(
        "检测→研判→经验→**再检测**闭环: 把已证实的研判经验 (人工 resolved 的攻击特征) "
        "提炼为 Sigma 规则草稿.\n\n"
        "- experience_text 入参直接给经验原文; 留空则自动向量召回经验库\n"
        "- 产出落 data/sigma_drafts/, 状态 draft — **永不自动下发设备** "
        "(检测规则改变全网告警面, 必须人工审批)\n"
        "- 同指纹 (title+logsource+condition) 幂等去重"
    ),
)
async def secops_detection_forge(req: ForgeRequest):
    from app.security.sigma_forge import forge_from_experience

    return await forge_from_experience(req)


@router.get(
    "/detection/drafts",
    summary="Sigma 规则草稿列表 (draft/approved 状态机)",
)
async def secops_detection_drafts():
    from app.security.sigma_forge import list_drafts

    return list_drafts()


@router.post(
    "/detection/drafts/{fid}/approve",
    summary="人工审批规则草稿 (draft → approved, 仅状态标记)",
    description=(
        "审批只改状态标记 — 本系统不自动下发任何设备; 下发由人用 Sigma 工具链 "
        "(pySigma 转换器/设备管理台) 执行. 幂等: 重复审批返回 already_approved."
    ),
)
async def secops_detection_approve(fid: str, req: DetectionApproveRequest):
    from app.security.sigma_forge import approve_draft

    return approve_draft(fid, reviewer=req.reviewer, note=req.note)
