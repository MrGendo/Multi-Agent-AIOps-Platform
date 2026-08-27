"""DeclarativeBase + 统一 naming convention.

为什么统一命名: Alembic autogenerate 对未命名的约束 (PK/UQ/FK/CK/IX)
会生成随机后缀名, 导致同一份模型在不同机器上 diff 不稳定.
统一 convention 后约束名可预测 (如 uq_alerts_fingerprint), 迁移可复现.
"""

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

# SQLAlchemy 官方推荐的 naming convention (Baked into MetaData)
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(referred_table_name)s_%(column_0_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """全项目统一的 ORM 基类."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)
