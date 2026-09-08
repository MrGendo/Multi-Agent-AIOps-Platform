"""Executor 流式事件旁路.

LangGraph graph.astream() 只产出节点级事件, Executor 内部 LLM 的 token 级流式
没有官方出口. 这里用 ContextVar + asyncio.Queue 把 token 从 tool_runner
外送给 aiops_service, 让前端能看到 Executor 正在生成文字, 减少空白等待.

用法:
  - aiops_service 在启动 graph.astream 前调 set_sink(queue), 然后把 graph.astream
    包成 Task (Task 自动复制当前 context, 所以 tool_runner 里 get_sink() 拿得到).
  - tool_runner 每次流式输出调 await emit({...}).
  - aiops_service 主循环 merge 自己的 "node event" 和 queue 里的 "token event",
    统一 yield 给 SSE.
"""

from __future__ import annotations

import asyncio
from contextvars import ContextVar
from typing import Any, Dict, Optional

_sink_var: ContextVar[Optional["asyncio.Queue[Dict[str, Any]]"]] = ContextVar(
    "executor_stream_sink", default=None
)
_step_var: ContextVar[int] = ContextVar("executor_current_step", default=0)
# 当前步骤所属专家 (skill name). 多专家 Send 并行时各分支 iteration 都从 1 重数,
# 前端必须靠 (skill, iteration) 复合键才能把事件归到正确泳道, 所以事件必须带 skill.
_skill_var: ContextVar[Optional[str]] = ContextVar("executor_current_skill", default=None)


def set_sink(queue: "asyncio.Queue[Dict[str, Any]]") -> None:
    _sink_var.set(queue)


def set_step(iteration: int, skill: Optional[str] = None) -> None:
    """记录当前步号与所属专家.

    skill 为 None 时保持原值不变 (兼容只更新步号的旧调用);
    显式传空串 "" 表示"无专家"场景, 会清掉之前的值.
    """
    _step_var.set(iteration)
    if skill is not None:
        _skill_var.set(skill)


def get_step() -> int:
    return _step_var.get()


_miss_count = 0
_emit_count = 0


async def emit(event: Dict[str, Any]) -> None:
    """把事件推到 aiops_service 的中转队列. 队列不存在或满了, 静默丢弃."""
    global _miss_count, _emit_count
    from loguru import logger  # 放函数内避免循环 import

    q = _sink_var.get()
    if q is None:
        _miss_count += 1
        # 前 5 次 + 每 20 次打一条, 避免日志爆炸
        if _miss_count <= 5 or _miss_count % 20 == 0:
            logger.warning(
                f"[stream_sink] ⚠ sink=None (miss #{_miss_count}) type={event.get('type')} "
                f"— ContextVar 没跨 LangGraph 任务传过来"
            )
        return
    event.setdefault("iteration", _step_var.get())
    # 补专家归属: tool_call / step_token 等事件由 tool_runner 发出, 它不知道 skill,
    # 统一在这里从 ContextVar 补 (调用方显式带过 skill 的不被覆盖)
    event.setdefault("skill", _skill_var.get())
    try:
        q.put_nowait(event)
        _emit_count += 1
        if _emit_count <= 3 or _emit_count % 50 == 0:
            logger.info(
                f"[stream_sink] emit #{_emit_count} type={event.get('type')} "
                f"iter={event.get('iteration')} qsize={q.qsize()}"
            )
    except asyncio.QueueFull:
        logger.warning(f"[stream_sink] queue full, drop type={event.get('type')}")
