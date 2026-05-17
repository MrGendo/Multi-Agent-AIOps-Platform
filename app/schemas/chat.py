"""RAG 聊天接口的数据模型."""

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    """RAG 聊天请求."""

    session_id: str = Field(default="default", description="会话 ID, 用于多轮对话")
    question: str = Field(..., description="用户问题", min_length=1, max_length=2000)
    top_k: int = Field(default=3, description="检索文档数", ge=1, le=10)
    web_search: bool = Field(default=False, description="是否启用受限联网搜索补充资料")
    mcp_tools: bool = Field(default=True, description="是否允许 RAG Chat 调用 MCP 只读工具")

    model_config = {
        "json_schema_extra": {
            "example": {
                "session_id": "session-001",
                "question": "Redis 内存使用率过高怎么处理?",
                "top_k": 3,
                "web_search": False,
                "mcp_tools": True,
            }
        }
    }
