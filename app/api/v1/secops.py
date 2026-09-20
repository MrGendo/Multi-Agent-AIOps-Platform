"""SecOps 安全告警研判接口 (流式 SSE).

POST /api/v1/secops/triage
  -> 接收 SecurityTriageRequest (session_id, query)
  -> 返回 SSE 事件流: start/domain_classified/triage/scout/analyst/critic/report/complete/error

与 /aiops/diagnose 同构, 前端复用同一 SSE 消费模式.
"""

import json
from pathlib import Path
from typing import AsyncIterator

from fastapi import APIRouter
from loguru import logger
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from app.security.service import stream_triage

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


_HISTORY_FILE = Path(__file__).resolve().parents[2] / "data" / "alert_history.jsonl"


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


@router.get("/history/stats", summary="历史存储统计 — 三类存储条数/体积/时间范围")
async def secops_history_stats():
    return history_mgmt.get_stats()


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
