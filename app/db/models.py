"""ORM 模型 — 四张核心表 (蓝图要求).

  alerts            告警表 (fingerprint 去重 + occurrence 累计)
  diagnostic_runs   诊断运行表 (状态机 + token 用量 + 乐观锁 version)
  tool_executions   工具调用明细 (排障回溯: 谁、传了什么、耗时)
  hitl_audit_logs   人工审批审计 (只增不改)

时间字段统一 UTC (timezone-aware), JSON 字段用 SQLAlchemy JSON 类型
(SQLite/PG 均可存, PG 侧为 JSON 列; 迁移里用 sa.JSON 保持两端一致).
"""

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def _utcnow() -> datetime:
    """统一 UTC 当前时间 (timezone-aware)."""
    return datetime.now(timezone.utc)


# ============================================================
# 运行状态枚举 (存 String, 避免跨库枚举迁移差异)
# ============================================================
class RunStatus:
    """diagnostic_runs.status 取值."""

    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    WAITING_HITL = "WAITING_HITL"


class ToolExecStatus:
    """tool_executions.status 取值."""

    OK = "ok"
    FAILED = "failed"


class Alert(Base):
    """告警表 — webhook 收到的 firing 告警, 按 fingerprint upsert."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    fingerprint: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    alertname: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    instance: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    source: Mapped[str] = mapped_column(String(64), default="alertmanager", nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)

    runs: Mapped[list["DiagnosticRun"]] = relationship(back_populates="alert")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Alert {self.fingerprint} x{self.occurrence_count}>"


class DiagnosticRun(Base):
    """诊断运行表 — 一次 stream_diagnose 的完整生命周期."""

    __tablename__ = "diagnostic_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # UUID str
    session_id: Mapped[str] = mapped_column(String(255), default="default", nullable=False, index=True)
    alert_id: Mapped[int | None] = mapped_column(
        ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True
    )
    query: Mapped[str] = mapped_column(Text, default="", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default=RunStatus.RUNNING, nullable=False, index=True)
    trace_id: Mapped[str] = mapped_column(String(64), default="", nullable=False)

    # usage 统计
    input_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tool_calls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    report: Mapped[str] = mapped_column(Text, default="", nullable=False)
    error: Mapped[str] = mapped_column(Text, default="", nullable=False)

    # 乐观锁: 每次更新 version+1, 不匹配则 CAS 失败
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )

    alert: Mapped[Alert | None] = relationship(back_populates="runs")
    tool_executions: Mapped[list["ToolExecution"]] = relationship(back_populates="run")
    hitl_logs: Mapped[list["HitlAuditLog"]] = relationship(back_populates="run")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<DiagnosticRun {self.id} {self.status}>"


class ToolExecution(Base):
    """工具调用明细 — run 内每次 tool_call 一行, 排障回溯用."""

    __tablename__ = "tool_executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("diagnostic_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tool_name: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    args: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    result_preview: Mapped[str] = mapped_column(Text, default="", nullable=False)  # 截断存储
    status: Mapped[str] = mapped_column(String(16), default=ToolExecStatus.OK, nullable=False)
    elapsed_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)

    run: Mapped[DiagnosticRun] = relationship(back_populates="tool_executions")


class HitlAuditLog(Base):
    """人工审批审计 — 只增不改 (append-only), 记录 HITL 决策."""

    __tablename__ = "hitl_audit_logs"
    __table_args__ = (
        UniqueConstraint("run_id", "decided_at", name="uq_hitl_run_decided"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("diagnostic_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    plan: Mapped[str] = mapped_column(Text, default="", nullable=False)
    approved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    approver: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)

    run: Mapped[DiagnosticRun] = relationship(back_populates="hitl_logs")
