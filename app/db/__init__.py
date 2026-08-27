"""关系型持久化包 (PostgreSQL 生产 / SQLite 开发).

设计红线: 持久化是「可选增强」—— 数据库不可用时诊断流程必须照常工作.
所有对外入口都在 session.py 的模块级 flag 控制下, init 失败 → 全部 no-op.
"""
