"""SkillRegistry: 启动时扫描 definitions/, 加载所有 SKILL.md, 全局单例.

设计:
  - 文件布局: app/skills/definitions/<skill_name>/SKILL.md
  - 进程级 lru_cache 单例 (启动时加载一次, 后续从内存取)
  - 强制要求兜底 Skill `generic_oncall` 存在, 保证 Router 永远有 fallback
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger

from app.skills.loader import SkillLoadError, load_skill_from_file
from app.skills.models import Skill

# Skill 定义目录: app/skills/definitions/<skill_name>/SKILL.md
_DEFINITIONS_DIR = Path(__file__).parent / "definitions"

# 兜底 Skill 名: Router 选不出来时使用
GENERIC_SKILL_NAME = "generic_oncall"


class SkillRegistry:
    """加载和管理所有 Skill."""

    def __init__(self, skills: Dict[str, Skill]) -> None:
        self._skills = skills

    def all(self) -> List[Skill]:
        return list(self._skills.values())

    def names(self) -> List[str]:
        return list(self._skills.keys())

    def get(self, name: str) -> Optional[Skill]:
        return self._skills.get(name)

    def get_or_generic(self, name: Optional[str]) -> Skill:
        """取指定 Skill, 不存在时回退到 generic_oncall.

        Raises:
            RuntimeError: 兜底 Skill 也缺失 (规约错误)
        """
        if name and name in self._skills:
            return self._skills[name]
        generic = self._skills.get(GENERIC_SKILL_NAME)
        if generic is None:
            raise RuntimeError(
                f"兜底 Skill {GENERIC_SKILL_NAME!r} 缺失, "
                f"请确认 app/skills/definitions/{GENERIC_SKILL_NAME}/SKILL.md 存在"
            )
        return generic

    def to_router_menu(self) -> str:
        """生成给 Router LLM 看的全部 Skill 菜单 (Markdown)."""
        cards = [s.to_router_card() for s in self._skills.values()]
        return "\n\n".join(cards)


def _scan_definitions(root: Path) -> Dict[str, Skill]:
    """扫描 definitions/ 目录加载所有 SKILL.md."""
    skills: Dict[str, Skill] = {}
    if not root.exists():
        logger.warning(f"[Skill] 定义目录不存在: {root}")
        return skills

    for skill_md in sorted(root.glob("*/SKILL.md")):
        try:
            skill = load_skill_from_file(skill_md)
        except SkillLoadError as e:
            logger.error(f"[Skill] 跳过 {skill_md}: {e}")
            continue

        if skill.name in skills:
            logger.warning(
                f"[Skill] 重名 {skill.name!r}, 后者覆盖前者: {skill_md}"
            )
        skills[skill.name] = skill

    return skills


@lru_cache(maxsize=1)
def get_skill_registry() -> SkillRegistry:
    """获取全局 SkillRegistry 单例 (启动时加载一次)."""
    skills = _scan_definitions(_DEFINITIONS_DIR)
    logger.info(
        f"[Skill] 已加载 {len(skills)} 个 Skill: {list(skills.keys())}"
    )
    if GENERIC_SKILL_NAME not in skills:
        logger.warning(
            f"[Skill] 兜底 Skill {GENERIC_SKILL_NAME!r} 缺失, Router 失败时无法回退"
        )
    return SkillRegistry(skills)
