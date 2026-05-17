"""AIOps 多智能体诊断接口 (流式 SSE).

POST /api/v1/aiops/diagnose
  -> 接收 DiagnosisRequest (session_id, query)
  -> 返回 SSE 事件流, 事件类型见 schemas/aiops.py EventType
"""

import json
from typing import AsyncIterator

from fastapi import APIRouter
from loguru import logger
from sse_starlette.sse import EventSourceResponse

from app.schemas.aiops import DiagnosisRequest
import app.services.aiops_service as aiops_service

router = APIRouter(prefix="/aiops", tags=["aiops"])


@router.post(
    "/diagnose",
    summary="AIOps 多智能体故障诊断 (流式)",
    description=(
        "基于 LangGraph Plan-Execute-Replan 模式的多智能体故障诊断.\n\n"
        "**SSE 事件类型**:\n"
        "- `start` - 流程启动\n"
        "- `plan` - Planner 完成, 给出初始诊断步骤\n"
        "- `step_complete` - Executor 完成单步, 含工具调用结果\n"
        "- `replan` - Replanner 调整剩余计划\n"
        "- `report` - 最终诊断报告 (Markdown)\n"
        "- `complete` - 流程结束\n"
        "- `error` - 异常\n\n"
        "**事件格式** (event=message):\n"
        "```json\n"
        '{\n'
        '  "type": "step_complete",\n'
        '  "stage": "step_executed",\n'
        '  "message": "完成第 2 步",\n'
        '  "data": {"iteration": 2, "step": "...", "result_preview": "..."}\n'
        '}\n'
        "```"
    ),
)
async def aiops_diagnose(req: DiagnosisRequest) -> EventSourceResponse:
    logger.info(f"[aiops] session={req.session_id}, q={req.query[:60]}...")

    async def event_generator() -> AsyncIterator[dict]:
        try:
            async for sse_event in aiops_service.stream_diagnose(
                req.query,
                session_id=req.session_id,
                resume_action=req.resume_action,
                action_approved=req.action_approved,
            ):
                yield {
                    "event": "message",
                    "data": json.dumps(sse_event, ensure_ascii=False),
                }
        except Exception as e:
            logger.exception(f"[aiops] stream 异常: {e}")
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
