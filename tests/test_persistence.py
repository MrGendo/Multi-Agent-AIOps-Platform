"""持久化层测试: init 降级 + CRUD 语义 + CAS + best-effort 吞异常.

离线约定: 全部跑在 tmp_path 的 SQLite 文件上, 不碰真实库.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from sqlalchemy import select

import app.db.session as db_session
from app.db.models import Alert, DiagnosticRun, RunStatus, ToolExecution
from app.db.persistence import RESULT_PREVIEW_MAX_CHARS, persistence


@pytest.fixture(autouse=True)
def _fresh_db(tmp_path):
    """每个测试用独立 SQLite 文件, 测完清理全局状态与 DATABASE_URL 环境变量."""
    url = f"sqlite+aiosqlite:///{tmp_path}/test.db"
    db_session.reset_for_tests(url)
    yield
    # asyncio engine 需要事件循环内 dispose; 直接清引用交由 GC, 状态复位是关键
    db_session.reset_for_tests()
    import os

    os.environ.pop("DATABASE_URL", None)


# ============================================================
# init / 降级
# ============================================================
async def test_init_enables_persistence():
    assert db_session.persistence_enabled is False
    assert await db_session.init_db() is True
    assert db_session.persistence_enabled is True


async def test_init_failure_disables_and_methods_noop(tmp_path):
    # 用一个「文件挡路」的路径让 mkdir 必败: blocker 是文件而非目录
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file")
    db_session.reset_for_tests(f"sqlite+aiosqlite:///{blocker}/sub/x.db")

    assert await db_session.init_db() is False
    assert db_session.persistence_enabled is False

    # 降级红线: 所有方法 no-op 返回 None/False, 绝不抛异常
    assert await persistence.record_alert(fingerprint="fp") is None
    assert await persistence.start_run(query="q") is None
    assert await persistence.set_status("rid", "FAILED") is False
    assert await persistence.finish_run("rid", RunStatus.SUCCESS) is False
    assert await persistence.log_tool_exec("rid", tool_name="t") is False
    assert await persistence.record_hitl("rid", action="approve") is False
    assert await persistence.recently_diagnosed("fp", 900) is None


# ============================================================
# alerts: upsert 语义
# ============================================================
async def test_record_alert_insert_then_upsert():
    aid1 = await persistence.record_alert(
        fingerprint="fp-1", alertname="HighCPU", severity="warning", instance="node-1"
    )
    assert isinstance(aid1, int)

    # 同 fingerprint 再来 → occurrence_count 递增, 字段更新, 不新增行
    aid2 = await persistence.record_alert(
        fingerprint="fp-1", alertname="HighCPU", severity="critical"
    )
    assert aid2 == aid1

    async with db_session.get_session() as sess:
        rows = (await sess.execute(select(Alert))).scalars().all()
    assert len(rows) == 1
    assert rows[0].occurrence_count == 2
    assert rows[0].severity == "critical"  # 被第二次调用覆盖
    assert rows[0].alertname == "HighCPU"  # 空值不覆盖


# ============================================================
# diagnostic_runs: 生命周期 + CAS
# ============================================================
async def test_run_lifecycle_with_cas():
    run_id = await persistence.start_run(query="诊断 CPU 高", session_id="s1", trace_id="t1")
    assert run_id

    async with db_session.get_session() as sess:
        row = (await sess.execute(select(DiagnosticRun))).scalar_one()
    assert row.status == RunStatus.RUNNING
    assert row.version == 1

    # 正确 version 的 CAS 更新成功
    assert await persistence.set_status(run_id, "WAITING_HITL", expected_version=1) is True
    # 过期 version 的 CAS 更新被拒绝
    assert await persistence.set_status(run_id, "SUCCESS", expected_version=1) is False

    ok = await persistence.finish_run(
        run_id,
        RunStatus.SUCCESS,
        input_tokens=100,
        output_tokens=50,
        total_tokens=150,
        tool_calls=3,
        duration_ms=1234,
        report="# 报告",
        expected_version=2,
    )
    assert ok is True

    async with db_session.get_session() as sess:
        row = (await sess.execute(select(DiagnosticRun))).scalar_one()
    assert row.status == RunStatus.SUCCESS
    assert row.total_tokens == 150
    assert row.tool_calls == 3
    assert row.version == 3  # start=1, set_status→2, finish→3


async def test_finish_run_on_missing_id_returns_false():
    assert await persistence.finish_run("no-such-id", RunStatus.SUCCESS) is False


# ============================================================
# tool_executions: 截断 + 状态映射
# ============================================================
async def test_log_tool_exec_truncates_result():
    run_id = await persistence.start_run(query="q")
    assert run_id is not None
    long_result = "x" * (RESULT_PREVIEW_MAX_CHARS + 500)
    assert await persistence.log_tool_exec(run_id, tool_name="sandbox", result=long_result) is True
    # dict 结果走 json 序列化路径
    assert await persistence.log_tool_exec(
        run_id, tool_name="probe", result={"a": 1}, status="failed", elapsed_ms=42
    ) is True

    async with db_session.get_session() as sess:
        rows = (
            await sess.execute(select(ToolExecution).order_by(ToolExecution.id))
        ).scalars().all()
    assert len(rows) == 2
    assert rows[0].result_preview.endswith("...")
    assert len(rows[0].result_preview) == RESULT_PREVIEW_MAX_CHARS + 3
    assert rows[1].status == "failed"
    assert rows[1].elapsed_ms == 42


# ============================================================
# hitl 审计 + 去重查询
# ============================================================
async def test_record_hitl_append_only():
    run_id = await persistence.start_run(query="q")
    assert run_id is not None
    assert await persistence.record_hitl(run_id, action="approve", plan="步骤1", approved=True, approver="ops") is True
    assert await persistence.record_hitl(run_id, action="reject", approved=False) is True


async def test_recently_diagnosed_by_fingerprint():
    # 未诊断过的 fingerprint → None (不去重)
    assert await persistence.recently_diagnosed("fp-unknown", 900) is None

    aid = await persistence.record_alert(fingerprint="fp-hot")
    run_id = await persistence.start_run(query="q", alert_id=aid)
    assert run_id
    ts = await persistence.recently_diagnosed("fp-hot", 900)
    assert isinstance(ts, datetime)
