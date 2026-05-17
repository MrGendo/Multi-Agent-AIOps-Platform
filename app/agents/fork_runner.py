"""§4 cc-haha 借鉴: Skill Fork 执行器.

把标记为 `context: fork` 的 Skill 当作独立子任务跑一个完整 plan-execute-replan,
最终只把 final answer 写回主线 state.response, 起到上下文隔离 + token 预算独立的作用.

适用场景:
  - 未来新增长任务 Skill 时使用, 例如长报告、联网研究、跨语言通告
  - 当前默认 7 个 OnCall Skill 均走 inline, 避免不必要的子图开销

设计要点:
  - 子图复用主图 build_aiops_graph(), 通过 state.inside_fork=True 防止无限递归 fork
  - 子图的 input 拼成 "用户问题 + Skill playbook" 让 Planner 直接基于 playbook 拆步
  - 子图异常 → 主线 response 设为 fallback 提示, 不中断整个 SSE 流

参考:
  cc-haha src/tools/SkillTool/SkillTool.ts:122 prepareForkedCommandContext + runAgent
"""

from __future__ import annotations

from loguru import logger

from app.agents.state import PlanExecuteState
from app.runtime.agent_harness import get_agent_harness
from app.runtime.transitions import (
    FORK_FAILED,
    FORK_SUCCESS,
    make_transition,
)
from app.skills import get_skill_registry


async def fork_skill_node(state: PlanExecuteState) -> PlanExecuteState:
    """以独立子图运行选中的 fork Skill.

    与主图差异:
      - 子图 state.inside_fork=True, route_after_skill 看到这个标记会退化为 inline
        (走 planner→executor→replanner), 不再 fork
      - 子图 input = "用户原问题 + Skill playbook", 让 Planner 直接基于 playbook 拆步
      - 子图 final answer (state.response) 直接成为主图的 response, 触发 END

    Args:
        state: 主图当前 state, 必须有 selected_skill 字段

    Returns:
        主图 state 增量, 包含:
          - response: fork 子图的最终报告 (或 fallback 提示)
          - past_steps: 一条 (step="[fork] <skill>", result=final_answer)
          - plan: 清空 (触发 should_end → END)
          - transition_history: fork_success 或 fork_failed
    """
    # 延迟 import 避免循环 (graph -> fork_runner -> graph)
    from app.agents.graph import build_aiops_graph

    user_input = state.get("input", "")
    skill_name = state.get("selected_skill", "")
    registry = get_skill_registry()
    skill = registry.get_or_generic(skill_name)

    logger.info(
        f"[ForkSkill] 启动 fork 子图: skill={skill.name} "
        f"display={skill.display_name} max_iters={skill.fork_max_iters}"
    )

    sub_graph = build_aiops_graph()
    sub_input = (
        f"# 主对话用户问题\n{user_input}\n\n"
        f"# 你需要按以下 Playbook 完成: {skill.display_name}\n"
        f"{skill.playbook}"
    )
    sub_state: PlanExecuteState = {
        "input": sub_input,
        "selected_skill": skill_name,
        # 关键: 标记子图, 防止 route_after_skill 再走 fork → 无限递归
        "inside_fork": True,
        # 透传父级 permission_mode (子图也走相同安全策略)
        "permission_mode": state.get("permission_mode", "") or get_agent_harness().default_permission_mode(),
    }

    try:
        result = await sub_graph.ainvoke(
            sub_state,
            # recursion_limit 给 fork_max_iters 留 3× 余量 (planner+executor+replanner 一轮算 3 节点)
            config={"recursion_limit": skill.fork_max_iters * 3 + 5},
        )
    except Exception as exc:
        logger.exception(f"[ForkSkill] 子图异常: {exc}")
        detail = f"{type(exc).__name__}: {exc}"
        fallback = (
            f"# Fork Skill 执行失败\n\n"
            f"Skill: {skill.display_name}\n"
            f"原因: {detail}\n\n"
            f"建议: 检查 SKILL.md 配置, 或临时把该 Skill 改回 `context: inline`."
        )
        return {
            "past_steps": [(f"[fork] {skill.display_name}", fallback)],
            "response": fallback,
            "plan": [],
            "transition_history": [
                make_transition("fork_skill", FORK_FAILED, detail),
            ],
        }

    final_answer = (result.get("response") or "").strip()
    if not final_answer:
        # 子图跑完了但没产出 response (理论上 replanner 兜底会填, 这里再保一层)
        logger.warning(f"[ForkSkill] 子图未产出 response, skill={skill.name}")
        final_answer = (
            f"# Fork Skill 完成但未产出报告\n\n"
            f"Skill: {skill.display_name}\n"
            f"子图迭代了 {result.get('iteration', 0)} 步, 但未生成最终报告."
        )
        return {
            "past_steps": [(f"[fork] {skill.display_name}", final_answer)],
            "response": final_answer,
            "plan": [],
            "transition_history": [
                make_transition("fork_skill", FORK_FAILED, "sub-graph empty response"),
            ],
        }

    logger.info(
        f"[ForkSkill] 子图完成: skill={skill.name} response_len={len(final_answer)} "
        f"sub_iter={result.get('iteration', 0)}"
    )

    return {
        "past_steps": [(f"[fork] {skill.display_name}", final_answer)],
        "response": final_answer,
        "plan": [],
        "transition_history": [
            make_transition(
                "fork_skill", FORK_SUCCESS,
                f"skill={skill.name} response_len={len(final_answer)} "
                f"sub_iter={result.get('iteration', 0)}",
            ),
        ],
    }
