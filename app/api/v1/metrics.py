"""Prometheus /metrics 端点.

暴露路径: /metrics (全局, 不在 /api/v1 前缀下, 与 Prometheus 抓取约定一致)

为什么用裸 Response 而不是 ApiResponse 包装:
  Prometheus 抓取器只认文本协议格式, 不能包业务 JSON 壳.
"""

from fastapi import APIRouter, Response

from app.core.metrics import PROMETHEUS_CONTENT_TYPE, render_metrics

router = APIRouter(tags=["metrics"])


@router.get(
    "/metrics",
    summary="Prometheus 指标抓取端点",
    description=(
    "Prometheus 文本协议格式. 核心指标: "
    "aiops_diagnostic_duration_seconds (MTTR), "
    "aiops_token_usage_total (成本), "
    "aiops_tool_calls_total (工具失败率/熔断), "
    "aiops_hitl_pending (审批队列)."
    ),
)
async def prometheus_metrics() -> Response:
    return Response(content=render_metrics(), media_type=PROMETHEUS_CONTENT_TYPE)
