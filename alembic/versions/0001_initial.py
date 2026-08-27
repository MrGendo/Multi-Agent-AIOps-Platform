"""initial schema: alerts / diagnostic_runs / tool_executions / hitl_audit_logs

Revision ID: 0001_initial
Revises:
Create Date: 2026-08-27

四张蓝图核心表 + 关键索引:
  - alerts.fingerprint         UNIQUE + INDEX (upsert 依据)
  - diagnostic_runs.status     INDEX (排障常用过滤)
  - diagnostic_runs.session_id INDEX
  - tool_executions.run_id     INDEX (FK, 回溯一次 run 的全部工具调用)
  - hitl_audit_logs.run_id     INDEX (FK)
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("fingerprint", sa.String(length=255), nullable=False),
        sa.Column("alertname", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("severity", sa.String(length=32), nullable=False, server_default=""),
        sa.Column("instance", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False, server_default="alertmanager"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alerts")),
        sa.UniqueConstraint("fingerprint", name=op.f("uq_alerts_fingerprint")),
    )
    op.create_index(op.f("ix_alerts_fingerprint"), "alerts", ["fingerprint"], unique=True)

    op.create_table(
        "diagnostic_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("session_id", sa.String(length=255), nullable=False, server_default="default"),
        sa.Column("alert_id", sa.Integer(), nullable=True),
        sa.Column("query", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="RUNNING"),
        sa.Column("trace_id", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("input_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("output_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tool_calls", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("report", sa.Text(), nullable=False),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            name=op.f("fk_diagnostic_runs_alerts_id_alert_id"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_diagnostic_runs")),
    )
    op.create_index(op.f("ix_diagnostic_runs_status"), "diagnostic_runs", ["status"], unique=False)
    op.create_index(op.f("ix_diagnostic_runs_session_id"), "diagnostic_runs", ["session_id"], unique=False)

    op.create_table(
        "tool_executions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("tool_name", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("args", sa.JSON(), nullable=False),
        sa.Column("result_preview", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="ok"),
        sa.Column("elapsed_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["diagnostic_runs.id"],
            name=op.f("fk_tool_executions_diagnostic_runs_id_run_id"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tool_executions")),
    )
    op.create_index(op.f("ix_tool_executions_run_id"), "tool_executions", ["run_id"], unique=False)

    op.create_table(
        "hitl_audit_logs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("plan", sa.Text(), nullable=False),
        sa.Column("approved", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("approver", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["diagnostic_runs.id"],
            name=op.f("fk_hitl_audit_logs_diagnostic_runs_id_run_id"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_hitl_audit_logs")),
        sa.UniqueConstraint("run_id", "decided_at", name=op.f("uq_hitl_audit_logs_run_id_decided_at")),
    )
    op.create_index(op.f("ix_hitl_audit_logs_run_id"), "hitl_audit_logs", ["run_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_hitl_audit_logs_run_id"), table_name="hitl_audit_logs")
    op.drop_table("hitl_audit_logs")
    op.drop_index(op.f("ix_tool_executions_run_id"), table_name="tool_executions")
    op.drop_table("tool_executions")
    op.drop_index(op.f("ix_diagnostic_runs_session_id"), table_name="diagnostic_runs")
    op.drop_index(op.f("ix_diagnostic_runs_status"), table_name="diagnostic_runs")
    op.drop_table("diagnostic_runs")
    op.drop_index(op.f("ix_alerts_fingerprint"), table_name="alerts")
    op.drop_table("alerts")
