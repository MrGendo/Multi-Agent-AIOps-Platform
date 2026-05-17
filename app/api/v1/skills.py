"""Skill 列表查询接口.

GET /api/v1/skills
  -> 列出全部已注册 Skill 的元信息, 供前端展示 Playbook 库

Skill 内部细节 (playbook 全文) 不通过此接口返回, 避免响应体过大.
playbook 内容只用于 Planner 内部消费.
"""

from typing import List

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.schemas.common import ApiResponse
from app.skills import get_skill_registry

router = APIRouter(prefix="/skills", tags=["skills"])


class SkillSummary(BaseModel):
    """Skill 给前端看的精简元信息."""

    name: str = Field(..., description="Skill 唯一标识")
    display_name: str = Field(..., description="人类可读名称")
    description: str = Field(..., description="一句话适用场景")
    triggers: List[str] = Field(default_factory=list, description="触发关键字")
    allowed_tools: List[str] = Field(default_factory=list, description="允许调用的工具白名单")
    risk_level: str = Field(..., description="风险等级: low / medium / high")


class SkillListData(BaseModel):
    """Skill 列表响应载荷."""

    total: int = Field(..., description="Skill 总数")
    skills: List[SkillSummary] = Field(default_factory=list, description="全部 Skill 元信息")


@router.get(
    "",
    response_model=ApiResponse[SkillListData],
    summary="列出全部已注册 Skill",
    description=(
        "返回当前 SkillRegistry 中已加载的全部 Skill 元信息 (不含 playbook 全文).\n\n"
        "Skill 在启动时从 `app/skills/definitions/*/SKILL.md` 加载, 修改后需重启服务."
    ),
)
async def list_skills() -> ApiResponse[SkillListData]:
    registry = get_skill_registry()
    summaries = [
        SkillSummary(
            name=s.name,
            display_name=s.display_name,
            description=s.description,
            triggers=s.triggers,
            allowed_tools=s.allowed_tools,
            risk_level=s.risk_level,
        )
        for s in registry.all()
    ]
    return ApiResponse.success(
        data=SkillListData(total=len(summaries), skills=summaries),
        message=f"已加载 {len(summaries)} 个 Skill",
    )
