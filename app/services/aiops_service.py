"""AIOps 多智能体诊断服务.

把 LangGraph 图的 astream 输出包装成统一格式的 SSE 事件流, 供前端消费.

事件类型 (见 schemas/aiops.py EventType):
  - start           流程启动
  - skill_selected  SkillRouter 选定 Skill (新增)
  - plan            Planner 输出初始计划
  - step_complete   Executor 完成单步
  - replan          Replanner 给出新计划
  - report          最终诊断报告
  - complete        流程结束
  - error           异常

设计要点:
  - 全程结构化事件 (字典), 由 API 层统一 JSON 编码
  - 异常被 try/except 捕获后转为 error 事件, 不让流中断
  - 单实例 graph: 在模块加载时构建一次, 避免每次请求重新编译
"""

import asyncio
import time
from typing import Any, AsyncIterator, Dict

from loguru import logger

from app.agents import build_aiops_graph
from app.agents.stream_sink import set_sink
from app.runtime.agent_harness import HarnessUsageStats, get_agent_harness
import app.services.chat_memory as chat_memory
from app.services.consolidation_worker import consolidate_diagnosis_report

# 模块级单例 (图编译有开销, 不要每次请求都建)
_graph = None
_agent_semaphore = asyncio.Semaphore(get_agent_harness().agent_max_concurrency())


def _get_graph():
    global _graph
    if _graph is None:
        _graph = build_aiops_graph()
    return _graph


def _make_event(
    event_type: str, stage: str, message: str = "", **data: Any
) -> Dict[str, Any]:
    """构造统一格式的 SSE 事件."""
    return {"type": event_type, "stage": stage, "message": message, "data": data}


async def stream_diagnose(
    query: str, *, session_id: str = "default", resume_action: bool = False, action_approved: bool = False
) -> AsyncIterator[Dict[str, Any]]:
    """流式诊断, yield 一系列结构化事件.

    Args:
        query:      用户输入 (告警描述 / 故障现象)
        session_id: 会话 ID, 用于日志关联

    Yields:
        Dict[str, Any]: SSE 事件字典
    """
    if _agent_semaphore.locked():
        logger.warning(f"[aiops] session={session_id} | 并发已满")
        yield _make_event(
            "error",
            "concurrency_limited",
            message="当前诊断任务较多，请稍后重试",
            max_concurrency=get_agent_harness().agent_max_concurrency(),
        )
        return

    async with _agent_semaphore:
        logger.info(f"[aiops] session={session_id} | query={query[:100]}...")
        harness = get_agent_harness()
        total_t0 = time.perf_counter()
        input_tokens = output_tokens = total_tokens = 0
        tool_calls_count = tool_ms = 0

        yield _make_event(
            "start",
            "diagnosis_init",
            message="开始故障诊断",
            query=query,
            session_id=session_id,
        )

        graph = _get_graph()

        # Executor 里 tool_runner 走 astream 的 token 会被 emit_stream 推到这个队列,
        # 主循环和 graph.astream 节点事件合并 yield, 让前端边跑边看.
        token_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=2048)
        set_sink(token_queue)  # 当前 context 设置, create_task 会复制这份 context
        done_sentinel: Dict[str, Any] = {"__done__": True}

        async def _graph_runner() -> None:
            config = {
                "configurable": {"thread_id": session_id},
                "recursion_limit": harness.graph_recursion_limit()
            }
            try:
                if resume_action:
                    # 更新状态并恢复执行
                    graph.update_state(config, {"remediation_approved": action_approved})
                    async for event in graph.astream(None, config=config):
                        await token_queue.put({"__node__": event})
                else:
                    async for event in graph.astream({"input": query}, config=config):
                        await token_queue.put({"__node__": event})
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await token_queue.put({"__error__": exc})
            finally:
                await token_queue.put(done_sentinel)

        runner_task = asyncio.create_task(_graph_runner())
        saw_error = False
        pending_error: Dict[str, Any] | None = None

        try:
            while True:
                item = await token_queue.get()
                if item is done_sentinel:
                    break
                if "__error__" in item:
                    exc = item["__error__"]
                    logger.exception(f"[aiops] session={session_id} | 诊断异常: {exc}")
                    pending_error = _make_event(
                        "error", "diagnosis_failed",
                        message=f"诊断失败: {type(exc).__name__}: {exc}",
                        error_type=type(exc).__name__,
                    )
                    saw_error = True
                    continue
                if "__node__" in item:
                    event = item["__node__"]
                    for node_name, node_output in event.items():
                        # §6 先发 transition_history, 再发常规节点事件
                        for tr in (node_output or {}).get("transition_history") or []:
                            yield _make_event(
                                "transition",
                                tr.get("reason", "unknown"),
                                message=tr.get("detail", ""),
                                node=tr.get("node", node_name),
                                ts=tr.get("ts", ""),
                                reason=tr.get("reason", ""),
                            )
                        async for sse_event in _convert_node_event(node_name, node_output):
                            if sse_event.get("type") == "report":
                                report_text = (sse_event.get("data") or {}).get("report") or ""
                                if report_text:
                                    try:
                                        await chat_memory.append_diagnosis_report(
                                            report_text, session_id=session_id
                                        )
                                        # Phase 3: 异步触发经验提炼
                                        asyncio.create_task(
                                            consolidate_diagnosis_report(session_id, query, report_text)
                                        )
                                    except Exception as exc:
                                        logger.warning(
                                            f"[aiops] 诊断报告缓存/经验提炼触发失败 session={session_id}: "
                                            f"{type(exc).__name__}: {exc}"
                                        )
                            yield sse_event
                    continue
                # 其他都是 Executor 推出来的 token/step_start/tool_call 事件, 直接转 SSE.
                etype = item.get("type", "token")
                payload = {k: v for k, v in item.items() if k != "type"}
                if etype == "usage":
                    input_tokens += int(payload.get("input_tokens") or 0)
                    output_tokens += int(payload.get("output_tokens") or 0)
                    total_tokens += int(payload.get("total_tokens") or 0)
                elif etype == "tool_call":
                    tool_calls_count += 1
                    tool_ms += int(payload.get("elapsed_ms") or 0)
                yield _make_event(etype, etype, message="", **payload)

            total_ms = int((time.perf_counter() - total_t0) * 1000)
            if total_tokens == 0:
                total_tokens = input_tokens + output_tokens
            usage_stats = HarnessUsageStats(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=total_tokens,
                total_ms=total_ms,
                tool_calls=tool_calls_count,
                tool_ms=tool_ms,
                run_kind="aiops_diagnosis",
            )
            budget_event = harness.build_budget_event(harness.evaluate_budget(usage_stats))
            if budget_event:
                yield _make_event(
                    budget_event["type"],
                    budget_event["stage"],
                    message=budget_event.get("detail", ""),
                    **(budget_event.get("data") or {}),
                )
            stats_event = harness.build_usage_stats_event(usage_stats)
            yield _make_event(
                stats_event["type"],
                stats_event["stage"],
                message=stats_event.get("detail", ""),
                **(stats_event.get("data") or {}),
            )
            if saw_error and pending_error is not None:
                # 诊断已失败: 统计照发 (token 已消耗), 但以 error 收尾 —
                # complete 会让前端把失败诊断标成「完成」, error 必须是终止信号
                yield pending_error
                return
            yield _make_event(
                "complete", "diagnosis_complete", message="诊断流程完成"
            )

        except asyncio.CancelledError:
            # 客户端断开连接, 不算错误, 静默处理
            logger.info(f"[aiops] session={session_id} | 客户端断开")
            runner_task.cancel()
            raise
        except Exception as e:
            logger.exception(f"[aiops] session={session_id} | 诊断异常: {e}")
            yield _make_event(
                "error",
                "diagnosis_failed",
                message=f"诊断失败: {type(e).__name__}: {e}",
                error_type=type(e).__name__,
            )
        finally:
            if not runner_task.done():
                runner_task.cancel()
                try:
                    await runner_task
                except (asyncio.CancelledError, Exception):
                    pass


async def _convert_node_event(
    node_name: str, node_output: Dict[str, Any]
) -> AsyncIterator[Dict[str, Any]]:
    """把 LangGraph 节点输出转成 SSE 事件."""
    if node_name == "orchestrator":
        skills = node_output.get("selected_skills", [])
        reason = node_output.get("skill_reason", "")
        response = node_output.get("response", "")
        yield _make_event(
            "skills_selected",
            "skills_selected",
            message=f"并行拉起专家: {', '.join(skills)}",
            skills=skills,
            reason=reason,
        )
        if response:
            yield _make_event(
                "report",
                "report_generated",
                message="Orchestrator 已终止诊断",
                report=response,
            )

    elif node_name == "planner":
        plan = node_output.get("plan", [])
        yield _make_event(
            "plan",
            "plan_created",
            message=f"诊断计划已生成, 共 {len(plan)} 步",
            plan=plan,
        )

    elif node_name == "executor":
        past = node_output.get("past_steps", [])
        iteration = node_output.get("iteration", 0)
        if past:
            step, result = past[-1]
            preview = result[:200] + ("..." if len(result) > 200 else "")
            yield _make_event(
                "step_complete",
                "step_executed",
                message=f"完成第 {iteration} 步",
                iteration=iteration,
                step=step,
                result_preview=preview,
            )

    elif node_name == "critic":
        passed = node_output.get("critic_passed", True)
        feedback = node_output.get("critic_feedback", "")
        if not passed:
            yield _make_event(
                "critic",
                "critic_rejected",
                message="评审员发现结果异常或幻觉，打回重写",
                feedback=feedback,
            )
        else:
            yield _make_event(
                "critic",
                "critic_passed",
                message="执行结果校验通过",
            )

    elif node_name == "replanner":
        response = node_output.get("response", "")
        new_plan = node_output.get("plan", [])
        if new_plan:
            yield _make_event(
                "replan",
                "plan_updated",
                message=f"调整计划, 剩余 {len(new_plan)} 步",
                plan=new_plan,
            )

    elif node_name == "remediation_planner":
        plan = node_output.get("remediation_plan", "")
        if plan and plan != "无需自愈":
            yield _make_event(
                "action_request",
                "waiting_for_approval",
                message="已生成自愈修复方案，等待人工授权",
                plan=plan,
            )

    elif node_name == "action_executor":
        yield _make_event(
            "report",
            "action_executed",
            message="自愈修复已执行完毕",
            report=node_output.get("response", ""),
        )

    elif node_name == "merger":
        response = node_output.get("response", "")
        if response:
            yield _make_event(
                "report",
                "report_generated",
                message="多专家会诊结束，已生成最终报告",
                report=response,
            )

    # 其他未识别节点忽略 (例如内部节点)
