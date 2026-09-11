"""告警目标存在性预检门 (Precondition Gate).

背景 (2026-09-08 真实事故): 用户环境根本没有「线上订单服务」和 MySQL, 但系统花
25 万 token / 15 分钟 / 118 次工具调用去诊断一个不存在的问题, 最后编出了
「MySQL 实例宕机」「网关上游失联」等无中生有的结论。

设计原则 — 默认放行 (fail-open):
  这道门是防烧钱闸, 不是新故障源。只在「证据确凿地证明目标不存在」时短路;
  任何不确定 (工具不可用/超时/远端域名/无法解析目标) 一律放行, 行为与现状一致。
  宁可放行诊断真问题, 不可误杀真告警。

判定三态:
  verified     目标存在 (端口有监听), 正常放行
  refuted      目标可验证且不存在 (本机端口 RST x2), 短路出「目标不存在」报告
  unverifiable 无法验证 (远端/无目标/工具失败/超时), 放行

全程不调 LLM: 规则提取目标 + MCP check_port 探测, 预算 < 10s。
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from typing import List, Literal, Optional

from loguru import logger
from pydantic import BaseModel, Field

from app.runtime.transitions import (
    PRECHECK_ENABLED_OFF,
    PRECHECK_TARGET_REFUTED,
    PRECHECK_OK,
    make_transition,
)

# ---- 目标提取规则 ----

# 常见服务 → 默认端口 (本机未写 host 时的判定对象)
_SERVICE_PORTS: dict[str, int] = {
    "mysql": 3306,
    "mariadb": 3306,
    "postgres": 5432,
    "postgresql": 5432,
    "redis": 6379,
    "mongo": 27017,
    "mongodb": 27017,
    "nginx": 80,
}

# 本机地址形态 (只有这些才允许 refuted 判定)
_LOCAL_HOSTS = ("127.0.0.1", "localhost", "0.0.0.0", "::1")

# 本机指称词: query 里出现这些词时, 未写 host 的服务默认按本机处理
_LOCAL_CONTEXT = (
    "本机", "我的电脑", "我电脑", "这台电脑", "这台机器", "我的机器",
    "本地", "localhost", "my computer", "my pc", "this machine",
)

_HOST_PORT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}|localhost|::1)[:：](\d{2,5})")
_PORT_RE = re.compile(r"(?:端口|port)\s*[:：]?\s*(\d{2,5})", re.IGNORECASE)
_PORT_ALT_RE = re.compile(r"(\d{2,5})\s*(?:端口|port)", re.IGNORECASE)


class RefutedTarget(BaseModel):
    kind: Literal["tcp_port"] = "tcp_port"
    spec: str = Field(..., description="如 127.0.0.1:3306")
    evidence: str = Field(..., description="证伪证据摘要")


class PrecheckVerdict(BaseModel):
    status: Literal["verified", "refuted", "unverifiable"]
    targets: List[RefutedTarget] = Field(default_factory=list)
    report: str = ""
    elapsed_ms: int = 0


def _extract_local_candidates(text: str) -> List[str]:
    """从 query 提取本机可验证的 host:port 候选 (去重, 保序). 只返回本机目标."""
    q = (text or "").lower()
    found: List[str] = []
    seen: set[str] = set()

    def add(host: str, port: int) -> None:
        key = f"{host}:{port}"
        if key not in seen:
            seen.add(key)
            found.append(key)

    # 1. 显式 host:port
    for host, port in _HOST_PORT_RE.findall(text or ""):
        if host.lower() in _LOCAL_HOSTS:
            add("127.0.0.1", int(port))

    # 2. 本机上下文 + 服务名 → 默认端口 (mysql→3306 等)
    #    注意 \b 在中英混排边界不生效 (「和MySQL慢」的 和|M 之间无词边界),
    #    用前后非 ASCII 字母断言替代
    local_ctx = any(w in q for w in _LOCAL_CONTEXT)
    for svc, port in _SERVICE_PORTS.items():
        if re.search(rf"(?<![a-z]){re.escape(svc)}(?![a-z])", q):
            if local_ctx or not _HOST_PORT_RE.search(text or ""):
                # 没写任何 host 时, 对服务名做本机默认探测 (诊断机视角)
                add("127.0.0.1", port)

    # 3. 显式端口: 「端口 N」与「N 端口」两种写法 (裸数字+端口词, 不限中文冒号格式)
    for port in _PORT_RE.findall(text or ""):
        if int(port) not in (80, 443):  # 80/443 几乎总有别的监听, 不做判据
            add("127.0.0.1", int(port))
    if not any(s.endswith(f":{p}") for s in found for p in _PORT_ALT_RE.findall(text or "")):
        for port in _PORT_ALT_RE.findall(text or ""):
            if int(port) not in (80, 443):
                add("127.0.0.1", int(port))

    return found


async def _probe_port(host: str, port: int) -> str:
    """单次 TCP 探测 (纯 stdlib, 不走 MCP).

    为什么不用 MCP check_port: 它的 SSRF 防护会拒绝回环地址
    ([拒绝] 127.0.0.1 是内网/回环地址, 不允许扫描), 而预检恰恰只探本机。
    原生 socket 连接结果语义: ConnectionRefusedError=RST 无监听 (可证伪),
    超时/其他异常 = 不可判定 (放行)。测试 monkeypatch 本函数注入结果。
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, limit=128), timeout=3.0
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return "open: connected"
    except ConnectionRefusedError:
        return "Connection refused (RST, no listener)"
    except asyncio.TimeoutError:
        return "timeout"
    except OSError as exc:
        return f"os-error: {type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001
        return f"probe-error: {type(exc).__name__}: {exc}"


def _is_refused(result: str) -> bool:
    """Connection refused = RST = 明确无监听. timeout/filtered 一律不算."""
    r = (result or "").lower()
    return "refused" in r or "connection refused" in r


def _is_open(result: str) -> bool:
    r = (result or "").lower()
    return "open" in r or "成功" in r or ("connected" in r and "refused" not in r)


def _build_refuted_report(targets: List[RefutedTarget], query: str) -> str:
    lines = [
        "# 已中止：诊断目标在当前环境不存在",
        "",
        f"**原始请求**：`{query.strip()[:200]}`",
        "",
        "预检探测发现以下目标在本机不存在，按「不诊断不存在的问题」原则直接中止，",
        "**未拉起任何专家、未消耗诊断 token**：",
        "",
    ]
    for t in targets:
        lines.append(f"- `{t.spec}` — {t.evidence}")
    lines += [
        "",
        "## 说明",
        "- `Connection refused` 表示 TCP RST（端口明确无进程监听），不是网络不通。",
        "- 若该服务实际部署在**远端主机**，请提供 `host:port`（如 `10.0.0.5:3306`）重新发起，我会对远端做完整诊断。",
        "- 若你预期它就在本机，请先启动该服务后重试。",
    ]
    return "\n".join(lines)


def precheck_enabled() -> bool:
    """env 总开关, 默认开 (AIOPS_PRECHECK_ENABLED=false 可回退旧行为)."""
    raw = os.environ.get("AIOPS_PRECHECK_ENABLED", "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    return True


async def run_precheck(query: str) -> PrecheckVerdict:
    """执行预检. 任何内部异常都退化为 unverifiable (fail-open)."""
    t0 = time.perf_counter()
    try:
        candidates = _extract_local_candidates(query)
        if not candidates:
            return PrecheckVerdict(
                status="unverifiable",
                elapsed_ms=int((time.perf_counter() - t0) * 1000),
            )

        refuted: List[RefutedTarget] = []
        verified_any = False
        for spec in candidates:
            host, _, port_s = spec.rpartition(":")
            port = int(port_s)
            # 每端口探 2 次, 2 次都 refused 才证伪 (防瞬时抖动)
            r1 = await _probe_port(host, port)
            r2 = await _probe_port(host, port)
            if _is_refused(r1) and _is_refused(r2):
                refuted.append(RefutedTarget(
                    spec=spec,
                    evidence="Connection refused x2（RST，端口无监听）",
                ))
            elif _is_open(r1) or _is_open(r2):
                verified_any = True
            # timeout/异常 → 不下结论 (unverifiable 语义, 不加入 refuted)

        elapsed = int((time.perf_counter() - t0) * 1000)
        if refuted and not verified_any:
            # 全部候选都被证伪 → 短路; 有任一目标活着 → 放行 (问题至少部分真实)
            return PrecheckVerdict(
                status="refuted",
                targets=refuted,
                report=_build_refuted_report(refuted, query),
                elapsed_ms=elapsed,
            )
        return PrecheckVerdict(
            status="verified" if verified_any else "unverifiable",
            elapsed_ms=elapsed,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"[Precheck] 内部异常, 放行: {type(exc).__name__}: {exc}")
        return PrecheckVerdict(
            status="unverifiable",
            elapsed_ms=int((time.perf_counter() - t0) * 1000),
        )


async def precheck_node(state: dict) -> dict:
    """LangGraph 节点: refuted 时填 response 短路整张图, 否则透传."""
    from app.agents.stream_sink import emit as emit_stream  # 惰性 import 防循环依赖

    query = state.get("input", "")

    if not precheck_enabled():
        logger.info("[Precheck] 开关关闭, 放行")
        return {
            "precheck_status": "unverifiable",
            "transition_history": [make_transition("precheck", PRECHECK_ENABLED_OFF, "")],
        }

    verdict = await run_precheck(query)
    logger.info(f"[Precheck] status={verdict.status} targets={[t.spec for t in verdict.targets]} elapsed={verdict.elapsed_ms}ms")

    if verdict.status == "refuted":
        # 与 orchestrator 的 out_of_scope 短路同构: response 已填 → 主图跳过专家
        await emit_stream({
            "type": "precheck",
            "status": "refuted",
            "message": "预检: 诊断目标在本机不存在, 已中止 (未拉起专家)",
            "targets": [t.spec for t in verdict.targets],
        })
        # report + complete 由 aiops_service 的节点事件转换层处理 (response 已填),
        # 这里再发一条 report 事件确保前端零改动可渲染
        await emit_stream({"type": "report", "report": verdict.report, "skill": ""})
        return {
            "precheck_status": "refuted",
            "response": verdict.report,
            "iteration": 0,
            "transition_history": [
                make_transition(
                    "precheck", PRECHECK_TARGET_REFUTED,
                    f"refuted={[(t.spec, t.evidence) for t in verdict.targets]}",
                ),
            ],
        }

    await emit_stream({
        "type": "precheck",
        "status": verdict.status,
        "message": f"预检通过 ({verdict.status}), 继续诊断",
    })
    return {
        "precheck_status": verdict.status,
        "transition_history": [make_transition("precheck", PRECHECK_OK, verdict.status)],
    }
