"""AIOps 多智能体接口的数据模型."""

from typing import Any, Dict, Literal

from pydantic import BaseModel, Field


class DiagnosisRequest(BaseModel):
    """AIOps 诊断请求."""

    session_id: str = Field(default="default", description="会话 ID (也是 thread_id)")
    query: str = Field(
        default="",
        description="告警内容 / 故障现象 / 运维问题",
        max_length=4000,
    )
    resume_action: bool = Field(default=False, description="是否是授权并继续执行修复方案的请求")
    action_approved: bool = Field(default=False, description="如果 resume_action=True，是否同意执行")

    model_config = {
        "json_schema_extra": {
            "example": {
                "session_id": "diag-001",
                "query": "数据库 CPU 使用率持续 100%, 已经 30 分钟, 业务受影响",
            }
        }
    }


# ============================================================
# SSE 事件 schema (仅用于 OpenAPI 文档示例, 实际 SSE 用 JSON 字符串)
# ============================================================
EventType = Literal[
    "start",           # 流程启动
    "skill_selected",  # SkillRouter 选定 Skill
    "plan",            # Planner 完成, 给出初始计划
    "step_start",      # Executor 开始单步
    "step_complete",   # Executor 完成单步
    "replan",          # Replanner 给出新计划
    "report",          # 生成最终报告
    "complete",        # 流程结束
    "error",           # 错误
]


class DiagnosisEvent(BaseModel):
    """诊断 SSE 事件 (示例 schema)."""

    type: EventType = Field(..., description="事件类型")
    stage: str = Field(..., description="阶段标识")
    message: str = Field(default="", description="人类可读的描述")
    data: Dict[str, Any] = Field(default_factory=dict, description="结构化数据载荷")
