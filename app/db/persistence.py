"""PersistenceService — 业务侧唯一入口, 全 async + best-effort.

设计红线: 所有方法吞异常只 warning, 绝不让持久化故障影响诊断流程.
未 init / init 失败 → 方法直接 no-op 返回 None/False.

方法清单:
  record_alert      按 fingerprint upsert (重复则 last_seen_at/occurrence_count 更新)
  start_run        建 RUNNING 行, 返回 run_id
  log_tool_exec    追加一条工具调用明细
  set_status       更新状态 (如 WAITING_HITL), 带 version CAS
  finish_run       写 usage/report/error + 状态终态 + version CAS 递增
  record_hitl      追加 HITL 审计 (只增不改)
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from loguru import logger
from sqlalchemy import select, update

from app.db import session as db_session
from app.db.models import (
    Alert,
    DiagnosticRun,
    HitlAuditLog,
    RunStatus,
    ToolExecStatus,
    ToolExecution,
)

# result_preview 截断长度 (防止工具返回 10KB+ 撑爆库)
RESULT_PREVIEW_MAX_CHARS = 2000


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _preview(value: Any, limit: int = RESULT_PREVIEW_MAX_CHARS) -> str:
    """把任意结果截断成可存字符串."""
    if value is None:
        return ""
    if not isinstance(value, str):
        try:
            value = json.dumps(value, ensure_ascii=False, default=str)
        except Exception:
            value = str(value)
    return value[:limit] + ("..." if len(value) > limit else "")


class PersistenceService:
    """best-effort 持久化封装. 单例 persistence 在模块底部."""

    # ---------- 内部: 拿 session 的统一入口 (disabled 时返回 None) ----------
    @staticmethod
    def _sess():
        """返回 session factory 的上下文管理器; disabled 时返回 None."""
        if not db_session.persistence_enabled:
            return None
        return db_session.get_session()

    @staticmethod
    async def _ensure_init() -> bool:
        """惰性 init: 首次调用尝试 init, 失败即永久禁用 (模块级 flag)."""
        if db_session.persistence_enabled:
            return True
        return await db_session.init_db()

    # ============================================================
    # alerts
    # ============================================================
    async def record_alert(
        self,
        *,
        fingerprint: str,
        alertname: str = "",
        severity: str = "",
        instance: str = "",
        payload: Optional[dict] = None,
        source: str = "alertmanager",
    ) -> Optional[int]:
        """按 fingerprint upsert. 返回 alert id (失败/禁用返回 None)."""
        try:
            if not await self._ensure_init():
                return None
            async with db_session.get_session() as sess:
                stmt = select(Alert).where(Alert.fingerprint == fingerprint)
                existing = (await sess.execute(stmt)).scalar_one_or_none()
                now = _utcnow()
                if existing is not None:
                    existing.last_seen_at = now
                    existing.occurrence_count = (existing.occurrence_count or 0) + 1
                    if alertname:
                        existing.alertname = alertname
                    if severity:
                        existing.severity = severity
                    if instance:
                        existing.instance = instance
                    if payload:
                        existing.payload = payload
                    alert_id = existing.id
                else:
                    row = Alert(
                        fingerprint=fingerprint,
                        alertname=alertname,
                        severity=severity,
                        instance=instance,
                        payload=payload or {},
                        source=source,
                        first_seen_at=now,
                        last_seen_at=now,
                        occurrence_count=1,
                    )
                    sess.add(row)
                    await sess.flush()
                    alert_id = row.id
                await sess.commit()
                return alert_id
        except Exception as exc:
            logger.warning(f"[db] record_alert 失败 (忽略): {type(exc).__name__}: {exc}")
            return None

    async def recently_diagnosed(self, fingerprint: str, window_sec: int) -> Optional[datetime]:
        """查同 fingerprint 在窗口内最近一次诊断时间 (去重判断). 失败返回 None (不去重).

        窗口外 (上次诊断早于 now-window_sec) 返回 None → 允许再次诊断.
        """
        try:
            if not await self._ensure_init():
                return None
            async with db_session.get_session() as sess:
                cutoff = _utcnow() - timedelta(seconds=max(0, window_sec))
                stmt = (
                    select(DiagnosticRun.created_at)
                    .join(Alert, DiagnosticRun.alert_id == Alert.id)
                    .where(Alert.fingerprint == fingerprint)
                    .where(DiagnosticRun.created_at >= cutoff)
                    .order_by(DiagnosticRun.created_at.desc())
                    .limit(1)
                )
                row = (await sess.execute(stmt)).first()
                return row[0] if row else None
        except Exception as exc:
            logger.warning(f"[db] recently_diagnosed 失败 (忽略): {type(exc).__name__ }: {exc}")
            return None

    # ============================================================
    # diagnostic_runs
    # ============================================================
    async def start_run(
        self,
        *,
        query: str,
        session_id: str = "default",
        alert_id: Optional[int] = None,
        trace_id: str = "",
    ) -> Optional[str]:
        """创建 RUNNING 行, 返回 run_id (UUID str)."""
        run_id = str(uuid.uuid4())
        try:
            if not await self._ensure_init():
                return None
            async with db_session.get_session() as sess:
                sess.add(
                    DiagnosticRun(
                        id=run_id,
                        session_id=session_id,
                        alert_id=alert_id,
                        query=query or "",
                        status=RunStatus.RUNNING,
                        trace_id=trace_id,
                        version=1,
                    )
                )
                await sess.commit()
                return run_id
        except Exception as exc:
            logger.warning(f"[db] start_run 失败 (忽略): {type(exc).__name__}: {exc}")
            return None

    async def set_status(self, run_id: str, status: str, *, expected_version: Optional[int] = None) -> bool:
        """更新状态 (如 WAITING_HITL). CAS: version 不匹配则放弃."""
        try:
            if not await self._ensure_init():
                return False
            async with db_session.get_session() as sess:
                stmt = (
                    update(DiagnosticRun)
                    .where(DiagnosticRun.id == run_id)
                    .values(
                        status=status,
                        version=DiagnosticRun.version + 1,
                        updated_at=_utcnow(),
                    )
                )
                if expected_version is not None:
                    stmt = stmt.where(DiagnosticRun.version == expected_version)
                res = await sess.execute(stmt)
                await sess.commit()
                return bool(getattr(res, "rowcount", 0))
        except Exception as exc:
            logger.warning(f"[db] set_status 失败 (忽略): {type(exc).__name__}: {exc}")
            return False

    async def finish_run(
        self,
        run_id: str,
        status: str,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        total_tokens: int = 0,
        tool_calls: int = 0,
        duration_ms: int = 0,
        report: str = "",
        error: str = "",
        expected_version: Optional[int] = None,
    ) -> bool:
        """终态写入 + version CAS 递增."""
        try:
            if not await self._ensure_init():
                return False
            async with db_session.get_session() as sess:
                stmt = (
                    update(DiagnosticRun)
                    .where(DiagnosticRun.id == run_id)
                    .values(
                        status=status,
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        total_tokens=total_tokens,
                        tool_calls=tool_calls,
                        duration_ms=duration_ms,
                        report=report or "",
                        error=error or "",
                        version=DiagnosticRun.version + 1,
                        updated_at=_utcnow(),
                    )
                )
                if expected_version is not None:
                    stmt = stmt.where(DiagnosticRun.version == expected_version)
                res = await sess.execute(stmt)
                await sess.commit()
                return bool(getattr(res, "rowcount", 0))
        except Exception as exc:
            logger.warning(f"[db] finish_run 失败 (忽略): {type(exc).__name__}: {exc}")
            return False

    # ============================================================
    # tool_executions
    # ============================================================
    async def log_tool_exec(
        self,
        run_id: str,
        *,
        tool_name: str,
        args: Optional[dict] = None,
        result: Any = None,
        status: str = ToolExecStatus.OK,
        elapsed_ms: int = 0,
    ) -> bool:
        """追加一条工具调用明细. result 会被截断存储."""
        try:
            if not await self._ensure_init():
                return False
            async with db_session.get_session() as sess:
                sess.add(
                    ToolExecution(
                        run_id=run_id,
                        tool_name=tool_name or "",
                        args=args or {},
                        result_preview=_preview(result),
                        status=ToolExecStatus.FAILED if status == "failed" else ToolExecStatus.OK,
                        elapsed_ms=int(elapsed_ms or 0),
                    )
                )
                await sess.commit()
                return True
        except Exception as exc:
            logger.warning(f"[db] log_tool_exec 失败 (忽略): {type(exc).__name__}: {exc}")
            return False

    # ============================================================
    # hitl_audit_logs
    # ============================================================
    async def record_hitl(
        self,
        run_id: str,
        *,
        action: str,
        plan: str = "",
        approved: bool = False,
        approver: str = "",
    ) -> bool:
        """追加 HITL 审计记录 (只增不改)."""
        try:
            if not await self._ensure_init():
                return False
            async with db_session.get_session() as sess:
                sess.add(
                    HitlAuditLog(
                        run_id=run_id,
                        action=action or "",
                        plan=plan or "",
                        approved=bool(approved),
                        approver=approver or "",
                        decided_at=_utcnow(),
                    )
                )
                await sess.commit()
                return True
        except Exception as exc:
            logger.warning(f"[db] record_hitl 失败 (忽略): {type(exc).__name__}: {exc}")
            return False


# 模块级单例: 业务代码统一 from app.db.persistence import persistence
persistence = PersistenceService()
