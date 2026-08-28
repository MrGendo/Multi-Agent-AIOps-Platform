"""Alembic 迁移与 ORM 模型漂移检测.

生产走 alembic upgrade head, 开发/测试走 Base.metadata.create_all —
两条路径建出的 schema 若有差异, 会出现「本地好的、生产缺列」的经典事故.
本测试用两条路径各建一份 SQLite, 逐表逐列比对.

约束: alembic 的 upgrade 需要运行在 alembic 环境里 — 直接用子进程跑
`alembic upgrade head` (DATABASE_URL 指向 tmp 库), 再用 sqlalchemy 检查.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect

ROOT = Path(__file__).resolve().parent.parent


def _normalize_cols(cols: dict) -> dict:
    """只比对会影响运行的结构属性, 忽略双方表示差异的细节."""
    out = {}
    for c in cols.values():
        out[c["name"]] = {
            "type": str(c["type"]).upper().split("(")[0],
            "nullable": c["nullable"],
        }
    return out


@pytest.fixture()
def two_schemas(tmp_path):
    """返回 (alembic 建的库, ORM 建的库) 的 inspector."""
    alembic_db = tmp_path / "alembic.db"
    orm_db = tmp_path / "orm.db"

    # 路径 1: alembic upgrade head (生产路径)
    import os

    env = dict(os.environ)
    env["DATABASE_URL"] = f"sqlite:///{alembic_db}"
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, f"alembic upgrade 失败:\n{proc.stdout}\n{proc.stderr}"

    # 路径 2: ORM create_all (开发路径)
    from app.db.base import Base
    import app.db.models  # noqa: F401 注册模型

    engine = create_engine(f"sqlite:///{orm_db}")
    Base.metadata.create_all(engine)

    insp_alembic = inspect(create_engine(f"sqlite:///{alembic_db}"))
    insp_orm = inspect(engine)
    return insp_alembic, insp_orm


def test_same_table_sets(two_schemas):
    insp_alembic, insp_orm = two_schemas
    a = set(insp_alembic.get_table_names()) - {"alembic_version"}
    o = set(insp_orm.get_table_names())
    assert a == o, f"表集合不一致: alembic-only={a - o}, orm-only={o - a}"


def test_no_column_drift(two_schemas):
    insp_alembic, insp_orm = two_schemas
    tables = set(insp_orm.get_table_names())
    for t in sorted(tables):
        a = _normalize_cols({c["name"]: c for c in insp_alembic.get_columns(t)})
        o = _normalize_cols({c["name"]: c for c in insp_orm.get_columns(t)})
        only_a = set(a) - set(o)
        only_o = set(o) - set(a)
        assert not only_a and not only_o, (
            f"表 {t} 列漂移: alembic-only={only_a}, orm-only={only_o}"
        )
        for col in set(a) & set(o):
            assert a[col]["type"] == o[col]["type"], (
                f"表 {t}.{col} 类型漂移: alembic={a[col]['type']} orm={o[col]['type']}"
            )


def test_alembic_single_head():
    """多 head = 有人忘了 merge, 生产 upgrade 会直接报错."""
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "heads"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    heads = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    assert len(heads) == 1, f"alembic 出现多 head: {heads}"
