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
