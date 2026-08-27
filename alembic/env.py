"""Alembic env — async 兼容 (sync_engine + run_sync 模式).

URL 解析优先级:
  1. 环境变量 DATABASE_URL (迁移本地临时库 / CI 最常用)
  2. app.config.settings.database_url (跟随应用配置)
  3. alembic.ini 的 sqlalchemy.url (兜底, 默认留空)

注意: 迁移用同步 driver URL (sqlite:/// / postgresql://),
     async driver 前缀 (sqlite+aiosqlite / postgresql+asyncpg) 会被自动剥掉,
     因为这里用 create_engine (sync) 跑 run_sync.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

# ============================================================
# 项目导入 (放在 fileConfig 之后避免 logging 冲突)
# ============================================================
from app.config import settings  # noqa: E402
from app.db.base import Base  # noqa: E402
import app.db.models  # noqa: E402, F401  确保模型注册进 metadata

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _to_sync_url(url: str) -> str:
    """async driver 前缀 → 同步 driver (迁移用同步引擎跑)."""
    if not url:
        return url
    replacements = {
        "sqlite+aiosqlite://": "sqlite://",
        "postgresql+asyncpg://": "postgresql://",
        "postgresql+psycopg://": "postgresql://",
    }
    for async_prefix, sync_prefix in replacements.items():
        if url.startswith(async_prefix):
            return sync_prefix + url[len(async_prefix):]
    return url


def _resolve_url() -> str:
    url = os.environ.get("DATABASE_URL") or settings.database_url or config.get_main_option("sqlalchemy.url")
    return _to_sync_url(url or "")


def run_migrations_offline() -> None:
    """离线模式: 只生成 SQL 不连库."""
    url = _resolve_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=url.startswith("sqlite"),
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """在线模式: sync engine + run_sync (官方 async 兼容写法)."""
    url = _resolve_url()
    cfg = config.get_section(config.config_ini_section) or {}
    cfg["sqlalchemy.url"] = url

    connectable = engine_from_config(
        cfg,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=url.startswith("sqlite"),
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
