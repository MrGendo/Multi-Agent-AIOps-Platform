"""调查子代理 (Investigator Subagent) — 决策/执行分离架构.

Analyst (决策 agent) 置信度不足时, 不再自己回 Scout 盲目重查, 而是
委托本子代理带着明确目标 (investigation_needs) 执行定向调查:

  Analyst: "还需要确认 X" ──► Investigator (独立 ReAct 循环, 只读工具池)
                                dns_lookup / ping / http_check / web_search
                                跑 2-4 轮工具调用
  Analyst ◄── 压缩后的发现 ("X 已确认/排除, 证据: ...") ──┘

设计要点 (借鉴 AIOps 域 subagents/runner.py 的 delegate 模式):
  - 决策 agent 只看结果摘要, 永不看原始工具日志 (上下文不被日志淹没)
  - 工具池硬白名单, 全只读, 无嵌套委托
  - 返回强制压缩: 只回「结论 + 关键证据」, 上限字符数截断
  - fail-soft: 工具不可用/LLM 失败返回「调查不可用」不阻塞主流程
"""

from __future__ import annotations

from typing import List

from loguru import logger
from pydantic import BaseModel, Field

from app.core.llm import get_chat_llm
from app.core.structured import ainvoke_structured

# 调查子代理可用的工具名 (MCP 只读探针 + web_search; 需对应 MCP server 在跑)
INVESTIGATOR_TOOLS = ("dns_lookup", "ping_host", "http_check", "web_search")

_MAX_FINDING_CHARS = 1200


class InvestigationFinding(BaseModel):
    """子代理调查结果的结构化输出 (强制压缩)."""

    objective: str = Field(..., description="本次调查要确认什么")
    conclusion: str = Field(..., description="结论: 确认了什么/排除了什么, 一两句话")
    key_evidence: List[str] = Field(
        default_factory=list,
        description="关键证据 (原样引用工具输出里的关键行, 最多 5 条)",
    )
    tools_used: List[str] = Field(default_factory=list, description="用过的工具名")
    still_unknown: str = Field(default="", description="仍无法确认的部分 (诚实标注)")


_SYSTEM_PROMPT = """你是安全研判团队里的调查执行员 (Investigator). 决策分析师 (Analyst) 给你一个明确的调查目标, 你用只读工具去取证并返回压缩结论.

纪律:
1. 只围绕目标取证, 不发散调查; 工具调用 2-4 次为宜, 拿到能回答目标的证据就停.
2. 工具查不到/超时/拒绝, 如实报告 still_unknown, 禁止编造结果.
3. 结论必须由 key_evidence 里的真实工具输出支撑; 证据原样引用关键行, 不要整段粘贴.
4. 返回即终结: 你只交回发现, 判定由 Analyst 做."""


def _get_tool(name: str):
    """惰性取单个 MCP 工具; 不存在返回 None."""
    try:
        from app.tools.mcp_loader import get_all_tools

        for t in get_all_tools():
            if t.name == name:
                return t
    except Exception:
        return None
    return None


def _format_finding(f: InvestigationFinding) -> str:
    """压缩成一段给 Analyst 看的文字."""
    lines = [f"[调查目标] {f.objective}", f"[结论] {f.conclusion}"]
    if f.key_evidence:
        lines.append("[证据]")
        lines.extend(f"  - {e[:200]}" for e in f.key_evidence[:5])
    if f.tools_used:
        lines.append(f"[工具] {', '.join(f.tools_used)}")
    if f.still_unknown:
        lines.append(f"[仍未知] {f.still_unknown}")
    text = "\n".join(lines)
    return text[:_MAX_FINDING_CHARS]


async def run_investigation(alert_text: str, objective: str, context: str = "") -> str:
    """执行一次定向调查, 返回压缩发现文本 (fail-soft).

    Args:
        alert_text: 原始告警 (子代理知道在查什么事件)
        objective:  调查目标 (来自 Analyst 的 investigation_needs)
        context:    已知 IOC/发现摘要 (避免重复查已知信息)
    """
    logger.info(f"[Investigator] 开始定向调查: {objective[:100]!r}")
    # 收集可用工具
    tools = []
    for name in INVESTIGATOR_TOOLS:
        t = _get_tool(name)
        if t is not None:
            tools.append(t)
    if not tools:
        logger.warning("[Investigator] 无可用只读工具 (MCP 未起?), 返回不可用")
        return (
            f"[调查不可用] 当前环境无只读探针工具 ({', '.join(INVESTIGATOR_TOOLS)} 均未加载), "
            "无法执行定向调查; 请基于已有证据研判或人工取证."
        )

    # ReAct 循环: LLM 决策调工具, 最多 4 轮
    from langchain_core.messages import AIMessage, HumanMessage

    llm = get_chat_llm(temperature=0, timeout=90, max_retries=2)
    # 关键: bind_tools 让 LLM 知道工具存在 (tool_runner 同款模式), 否则
    # LLM 永远只输出文本不调工具, 调查结论退化为推理编造 (E2E 真实抓到)
    bound_llm = llm.bind_tools(tools)
    messages: list = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        HumanMessage(content=(
            f"# 原始告警\n{alert_text[:800]}\n\n"
            f"# 已知上下文 (勿重复调查)\n{context[:600] or '(无)'}\n\n"
            f"# 调查目标\n{objective}\n\n"
            f"可用工具: {', '.join(t.name for t in tools)}. 开始调查."
        )),
    ]
    tool_log: List[str] = []
    try:
        for _round in range(4):
            ai: AIMessage = await bound_llm.ainvoke(messages)
            messages.append(ai)
            if not ai.tool_calls:
                break
            for tc in ai.tool_calls:
                name = tc.get("name", "")
                tool = next((t for t in tools if t.name == name), None)
                if tool is None:
                    messages.append({"role": "tool", "tool_call_id": tc.get("id", ""),
                                     "content": f"未知工具 {name}"})
                    continue
                try:
                    from app.runtime.tool_runner import _safe_invoke_tool

                    result = await _safe_invoke_tool(tool, {"name": name, "args": tc.get("args", {})})
                except Exception as exc:
                    result = f"工具执行失败: {exc}"
                result_text = str(result)[:1500]
                tool_log.append(f"{name}: {result_text[:200]}")
                messages.append({"role": "tool", "tool_call_id": tc.get("id", ""), "content": result_text})
    except Exception as exc:
        logger.warning(f"[Investigator] ReAct 执行异常 (fail-soft): {exc}")

    # 压缩输出: 结构化提炼 (LLM 失败退化为原始文本截断)
    transcript = "\n".join(str(m)[:400] for m in messages[1:])
    try:
        finding = await ainvoke_structured(
            llm=llm,
            schema_cls=InvestigationFinding,
            messages=[
                {"role": "system", "content": "把调查过程压缩为结构化发现, 证据必须来自上面的工具输出."},
                {"role": "user", "content": f"目标: {objective}\n\n调查记录:\n{transcript[:4000]}"},
            ],
            model_name="glm-5.3-flash",
        )
        out = _format_finding(finding)
    except Exception as exc:
        logger.warning(f"[Investigator] 结果压缩失败, 退化原始摘要: {exc}")
        out = f"[调查目标] {objective}\n[工具记录]\n" + "\n".join(tool_log[:8])[:_MAX_FINDING_CHARS]

    logger.info(f"[Investigator] 调查完成 ({len(out)} 字, 工具 {len(tool_log)} 次)")
    return out
