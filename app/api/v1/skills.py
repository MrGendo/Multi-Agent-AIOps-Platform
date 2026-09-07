"""Skill 查询接口.

GET /api/v1/skills
  -> 列出全部已注册 Skill 的元信息, 供前端展示 Playbook 库

GET /api/v1/skills/{name}
  -> 单个 Skill 详情: 详情接口返回 playbook 全文, 供前端抽屉完整渲染;
     skill 不存在时抛 NotFoundError, 由全局异常处理器转 404 ApiResponse.

列表接口不返回 playbook (避免响应体过大), 全文只在详情接口按需下发.
"""

from typing import List

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.exceptions import NotFoundError
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


class SkillDetail(SkillSummary):
    """Skill 详情: 在列表元信息之上追加 playbook 全文."""

    playbook: str = Field(..., description="完整 Markdown playbook 正文")


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


@router.get(
    "/{name}",
    response_model=ApiResponse[SkillDetail],
    summary="查询单个 Skill 详情 (含 playbook 全文)",
    description="按 name 返回 Skill 元信息与完整 Markdown playbook; 不存在时返回 404.",
)
async def get_skill(name: str) -> ApiResponse[SkillDetail]:
    skill = get_skill_registry().get(name)
    if skill is None:
        raise NotFoundError(f"skill {name} 不存在")
    return ApiResponse.success(
        data=SkillDetail(
            name=skill.name,
            display_name=skill.display_name,
            description=skill.description,
            triggers=skill.triggers,
            allowed_tools=skill.allowed_tools,
            risk_level=skill.risk_level,
            playbook=skill.playbook,
        ),
        message=skill.display_name,
    )
