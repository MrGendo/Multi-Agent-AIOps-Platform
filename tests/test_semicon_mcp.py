"""MCP 协议层测试: semicon_server 经 FastMCP Client 真实工具调用.

只测「工具暴露是否正确」: 名称/参数 schema/返回 JSON 可序列化.
不依赖网络端口 — FastMCP Client in-memory 直连.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "mcp_servers"))


@pytest.fixture(scope="module")
async def mcp_tool_list():
    """连接 semicon_server 的 mcp 实例, 返回工具列表."""
    from fastmcp import Client

    import semicon_server

    async with Client(semicon_server.mcp) as c:
        return await c.list_tools()


async def test_five_tools_exposed(mcp_tool_list):
    names = {t.name for t in mcp_tool_list}
    assert {
        "secs_link_status",
        "chamber_pressure",
        "chiller_temp",
        "wafer_yield_trend",
        "equipment_alarm_list",
    } <= names


async def test_tool_schemas_have_required_params(mcp_tool_list):
    tools = {t.name: t for t in mcp_tool_list}
    for name in [
        "secs_link_status",
        "chamber_pressure",
        "chiller_temp",
        "equipment_alarm_list",
    ]:
        schema = tools[name].inputSchema
        if not isinstance(schema, dict):
            schema = json.loads(schema)
        assert "equipment_id" in schema.get("properties", {}), name
        assert schema.get("required") == ["equipment_id"], name

    yschema = tools["wafer_yield_trend"].inputSchema
    if not isinstance(yschema, dict):
        yschema = json.loads(yschema)
    assert yschema["properties"]["equipment_id"]["type"] == "string"
    assert yschema["properties"]["hours"]["type"] == "integer"
    assert yschema.get("required") == ["equipment_id"]


async def test_call_tool_via_mcp_client():
    """in-memory Client 真实调用工具, 验证 MCP 协议层完整可用 (list→call→parse)."""
    from fastmcp import Client

    import semicon_server

    async with Client(semicon_server.mcp) as c:
        result = await c.call_tool("chamber_pressure", {"equipment_id": "EQP-001"})
    # FastMCP 返回 content 列表; 文本内容应为可解析 JSON
    text = result.content[0].text
    payload = json.loads(text)
    assert payload["equipment_id"] == "EQP-001"
    assert payload["alarm"] is False  # EQP-001 是 normal 剧本
