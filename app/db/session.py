"""Async engine + session 工厂, 含「DB 不可用 → 持久化整体禁用」降级逻辑.

设计红线 (工业级要求):
  - init 失败不抛异常, 只打 warning, 并置 persistence_enabled=False
  - 之后所有操作 no-op, 诊断流程完全不受影响
  - SQLite 默认开 WAL (读写并发友好, webhook 高频写入不阻塞读取)

用法:
    from app.db.session import get_session, persistence_enabled
    async with get_session() as session:
        ...
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator, Optional

from loguru import logger
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import settings

# ============================================================
# 模块级状态: 持久化是否可用
# ============================================================
persistence_enabled: bool = False
_engine: Optional[AsyncEngine] = None
_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


def _resolve_database_url() -> str:
    """环境变量 DATABASE_URL 优先 (与 Alembic env.py 保持一致), 其次 settings."""
    return os.environ.get("DATABASE_URL") or settings.database_url


def _ensure_sqlite_parent_dir(url: str) -> None:
    """sqlite 相对路径时确保父目录存在 (默认 ./data/aiops.db)."""
    if url.startswith("sqlite"):
        # sqlite+aiosqlite:///./data/aiops.db → ./data/aiops.db
        part = url.split("///", 1)[-1]
        if part and not part.startswith(":memory:") and part != "":
            p = Path(part)
            if p.parent and not p.parent.exists():
                p.parent.mkdir(parents=True, exist_ok=True)


def _sqlite_wal_pragma(engine: AsyncEngine) -> None:
    """SQLite 连接时开 WAL + busy_timeout (async engine 的 sync dbapi 事件)."""

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):  # pragma: no cover
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.execute("PRAGMA synchronous=NORMAL")
        finally:
            cursor.close()


async def init_db(create_tables: bool = True) -> bool:
    """初始化 engine + 建表. 成功返回 True, 失败置 disabled 并返回 False.

    生产环境应该用 Alembic 管理表结构 (alembic upgrade head),
    create_tables=True 是开发便利 (SQLite 首启自动建表).
    """
    global persistence_enabled, _engine, _session_factory

    if persistence_enabled:
        return True

    url = _resolve_database_url()
    try:
        _ensure_sqlite_parent_dir(url)
        _engine = create_async_engine(
            url,
            echo=settings.db_echo,
            echo_pool=False,
            pool_pre_ping=True,
            future=True,
        )
        if url.startswith("sqlite"):
            _sqlite_wal_pragma(_engine)

        # 连通性验证 (失败即禁用, 不抛)
        async with _engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

        if create_tables:
            # dev 便利: 未跑 alembic 时自动建表 (checkfirst)
            from app.db.base import Base
            import app.db.models  # noqa: F401 确保模型注册

            async with _engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

        _session_factory = async_sessionmaker(
            bind=_engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
        persistence_enabled = True
        logger.info(f"[db] 持久化已启用: {_safe_url(url)}")
        return True
    except Exception as exc:
        logger.warning(
            f"[db] 持久化初始化失败, 已整体禁用 (诊断流程不受影响): "
            f"{type(exc).__name__}: {exc}"
        )
        persistence_enabled = False
        _engine = None
        _session_factory = None
        return False


def _safe_url(url: str) -> str:
    """日志里隐藏密码."""
    if "@" in url and "://" in url:
        scheme, rest = url.split("://", 1)
        if "@" in rest:
            cred, host = rest.rsplit("@", 1)
            if ":" in cred:
                user = cred.split(":", 1)[0]
                return f"{scheme}://{user}:***@{host}"
    return url


async def close_db() -> None:
    """关闭 engine (应用 shutdown 时调用, best-effort)."""
    global persistence_enabled, _engine, _session_factory
    if _engine is not None:
        try:
            await _engine.dispose()
        except Exception as exc:  # pragma: no cover
            logger.warning(f"[db] engine dispose 失败: {exc}")
    persistence_enabled = False
    _engine = None
    _session_factory = None


@asynccontextmanager
async def get_session() -> AsyncIterator[AsyncSession]:
    """拿到一个 AsyncSession; 未启用持久化时直接抛 RuntimeError 由调用方 no-op.

    PersistenceService 会在 persistence_enabled=False 时根本不走到这里.
    """
    if not persistence_enabled or _session_factory is None:
        raise RuntimeError("persistence disabled")
    async with _session_factory() as session:
        yield session


def reset_for_tests(database_url: str | None = None) -> None:
    """测试辅助: 重置模块状态, 下次 init_db 用新 URL (或环境变量)."""
    global persistence_enabled, _engine, _session_factory
    persistence_enabled = False
    _engine = None
    _session_factory = None
    if database_url is not None:
        os.environ["DATABASE_URL"] = database_url
