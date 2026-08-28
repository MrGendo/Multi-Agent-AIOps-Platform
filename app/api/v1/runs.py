"""诊断 run / 告警查询 API — 持久化层的读取路径.

写入侧在 webhook (record_alert / start_run / finish_run), 这里补齐读取:
  GET /runs           分页列表 (时间倒序, 可按 status 过滤)
  GET /runs/{id}      单条详情 + 工具调用明细 + HITL 审计
  GET /alerts         告警聚合列表 (时间倒序, occurrence_count 保留)
  GET /alerts/{fp}    单 fingerprint 告警 + 关联的全部诊断 run

持久化禁用时返回明确的 degraded 标记 (而非 500), 前端可提示「未落库」.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.db import session as db_session
from app.db.models import Alert, DiagnosticRun, HitlAuditLog, ToolExecution
from app.schemas.common import ApiResponse

router = APIRouter(prefix="/runs", tags=["runs"])
alerts_router = APIRouter(prefix="/alerts", tags=["alerts"])


# ============================================================
# Schema
# ============================================================
class RunSummary(BaseModel):
    run_id: str
    session_id: str
    alert_id: Optional[int] = None
    query: str = Field(default="", description="诊断输入 (截断预览)")
    status: str
    total_tokens: int = 0
    tool_calls: int = 0
    duration_ms: int = 0
    error: str = ""
    created_at: str = ""
    finished_version: int = 0


class RunListData(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[RunSummary]
    degraded: bool = Field(default=False, description="持久化不可用, 数据不完整")


class ToolExecItem(BaseModel):
    tool_name: str
    status: str
    elapsed_ms: int
    result_preview: str
    created_at: str = ""


class HitlItem(BaseModel):
    action: str
    approved: bool
    approver: str
    decided_at: str = ""


class RunDetailData(BaseModel):
    run: RunSummary
    tool_executions: List[ToolExecItem]
    hitl_audit: List[HitlItem]


class AlertItem(BaseModel):
    fingerprint: str
    alertname: str
    severity: str
    instance: str
    occurrence_count: int
    first_seen_at: str = ""
    last_seen_at: str = ""


class AlertListData(BaseModel):
    total: int
    items: List[AlertItem]
    degraded: bool = False


class AlertDetailData(BaseModel):
    alert: AlertItem
    runs: List[RunSummary]


def _iso(v: Any) -> str:
    return v.isoformat() if v is not None else ""


def _degraded() -> ApiResponse[RunListData]:
    return ApiResponse(
        code="DEGRADED",
        message="持久化不可用 (init 失败或未配置), 无历史数据",
        data=RunListData(total=0, page=1, page_size=0, items=[], degraded=True),
    )


# ============================================================
# /runs
# ============================================================
@router.get("", summary="诊断 run 分页列表")
async def list_runs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None, description="按状态过滤: RUNNING/SUCCESS/FAILED/WAITING_HITL"),
) -> ApiResponse[RunListData]:
    if not db_session.persistence_enabled:
        return _degraded()

    try:
        async with db_session.get_session() as sess:
            base = select(DiagnosticRun)
            if status:
                base = base.where(DiagnosticRun.status == status)
            total = (await sess.execute(select(func.count()).select_from(base.subquery()))).scalar() or 0

            rows = (
                await sess.execute(
                    base.order_by(DiagnosticRun.created_at.desc())
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            ).scalars().all()

            items = [
                RunSummary(
                    run_id=r.id,
                    session_id=r.session_id,
                    alert_id=r.alert_id,
                    query=(r.query or "")[:200],
                    status=r.status,
                    total_tokens=r.total_tokens or 0,
                    tool_calls=r.tool_calls or 0,
                    duration_ms=r.duration_ms or 0,
                    error=(r.error or "")[:300],
                    created_at=_iso(r.created_at),
                    finished_version=r.version or 0,
                )
                for r in rows
            ]
            return ApiResponse(
                data=RunListData(total=total, page=page, page_size=page_size, items=items)
            )
    except Exception as exc:
        logger.warning(f"[runs] list_runs 查询失败: {exc}")
        return _degraded()


@router.get("/{run_id}", summary="诊断 run 详情 (含工具明细与 HITL 审计)")
async def get_run(run_id: str) -> ApiResponse[RunDetailData]:
    if not db_session.persistence_enabled:
        return ApiResponse(code="DEGRADED", message="持久化不可用", data=None)  # type: ignore[arg-type]

    try:
        async with db_session.get_session() as sess:
            r = (
                await sess.execute(select(DiagnosticRun).where(DiagnosticRun.id == run_id))
            ).scalar_one_or_none()
            if r is None:
                return ApiResponse(code="NOT_FOUND", message=f"run {run_id} 不存在", data=None)  # type: ignore[arg-type]

            tools = (
                await sess.execute(
                    select(ToolExecution)
                    .where(ToolExecution.run_id == run_id)
                    .order_by(ToolExecution.id)
                )
            ).scalars().all()

            hitl = (
                await sess.execute(
                    select(HitlAuditLog)
                    .where(HitlAuditLog.run_id == run_id)
                    .order_by(HitlAuditLog.id)
                )
            ).scalars().all()

            detail = RunDetailData(
                run=RunSummary(
                    run_id=r.id,
                    session_id=r.session_id,
                    alert_id=r.alert_id,
                    query=r.query or "",
                    status=r.status,
                    total_tokens=r.total_tokens or 0,
                    tool_calls=r.tool_calls or 0,
                    duration_ms=r.duration_ms or 0,
                    error=r.error or "",
                    created_at=_iso(r.created_at),
                    finished_version=r.version or 0,
                ),
                tool_executions=[
                    ToolExecItem(
                        tool_name=t.tool_name,
                        status=t.status,
                        elapsed_ms=t.elapsed_ms or 0,
                        result_preview=t.result_preview or "",
                        created_at=_iso(t.created_at),
                    )
                    for t in tools
                ],
                hitl_audit=[
                    HitlItem(
                        action=h.action,
                        approved=h.approved,
                        approver=h.approver,
                        decided_at=_iso(h.decided_at),
                    )
                    for h in hitl
                ],
            )
            return ApiResponse(data=detail)
    except Exception as exc:
        logger.warning(f"[runs] get_run 查询失败: {exc}")
        return ApiResponse(code="DEGRADED", message="查询失败", data=None)  # type: ignore[arg-type]


# ============================================================
# /alerts
# ============================================================
def _alert_item(a: Alert) -> AlertItem:
    return AlertItem(
        fingerprint=a.fingerprint,
        alertname=a.alertname or "",
        severity=a.severity or "",
        instance=a.instance or "",
        occurrence_count=a.occurrence_count or 0,
        first_seen_at=_iso(a.first_seen_at),
        last_seen_at=_iso(a.last_seen_at),
    )


@alerts_router.get("", summary="告警聚合列表 (按 fingerprint)")
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> ApiResponse[AlertListData]:
    if not db_session.persistence_enabled:
        return ApiResponse(
            code="DEGRADED",
            message="持久化不可用",
            data=AlertListData(total=0, items=[], degraded=True),
        )
    try:
        async with db_session.get_session() as sess:
            total = (await sess.execute(select(func.count(Alert.id)))).scalar() or 0
            rows = (
                await sess.execute(
                    select(Alert)
                    .order_by(Alert.last_seen_at.desc())
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            ).scalars().all()
            return ApiResponse(
                data=AlertListData(total=total, items=[_alert_item(a) for a in rows])
            )
    except Exception as exc:
        logger.warning(f"[alerts] list_alerts 查询失败: {exc}")
        return ApiResponse(
            code="DEGRADED", message="查询失败", data=AlertListData(total=0, items=[], degraded=True)
        )


@alerts_router.get("/{fingerprint}", summary="单告警详情 + 关联诊断 runs")
async def get_alert(fingerprint: str) -> ApiResponse[AlertDetailData]:
    if not db_session.persistence_enabled:
        return ApiResponse(code="DEGRADED", message="持久化不可用", data=None)  # type: ignore[arg-type]
    try:
        async with db_session.get_session() as sess:
            a = (
                await sess.execute(select(Alert).where(Alert.fingerprint == fingerprint))
            ).scalar_one_or_none()
            if a is None:
                return ApiResponse(code="NOT_FOUND", message=f"告警 {fingerprint} 不存在", data=None)  # type: ignore[arg-type]

            runs = (
                await sess.execute(
                    select(DiagnosticRun)
                    .where(DiagnosticRun.alert_id == a.id)
                    .order_by(DiagnosticRun.created_at.desc())
                )
            ).scalars().all()

            data = AlertDetailData(
                alert=_alert_item(a),
                runs=[
                    RunSummary(
                        run_id=r.id,
                        session_id=r.session_id,
                        alert_id=r.alert_id,
                        query=(r.query or "")[:200],
                        status=r.status,
                        total_tokens=r.total_tokens or 0,
                        tool_calls=r.tool_calls or 0,
                        duration_ms=r.duration_ms or 0,
                        error=(r.error or "")[:300],
                        created_at=_iso(r.created_at),
                        finished_version=r.version or 0,
                    )
                    for r in runs
                ],
            )
            return ApiResponse(data=data)
    except Exception as exc:
        logger.warning(f"[alerts] get_alert 查询失败: {exc}")
        return ApiResponse(code="DEGRADED", message="查询失败", data=None)  # type: ignore[arg-type]
