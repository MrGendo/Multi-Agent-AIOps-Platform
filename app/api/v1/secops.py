"""SecOps 安全告警研判接口 (流式 SSE).

POST /api/v1/secops/triage
  -> 接收 SecurityTriageRequest (session_id, query)
  -> 返回 SSE 事件流: start/domain_classified/triage/scout/analyst/critic/report/complete/error

与 /aiops/diagnose 同构, 前端复用同一 SSE 消费模式.
"""

import json
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
