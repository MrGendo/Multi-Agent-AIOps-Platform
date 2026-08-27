"""Prometheus 遥测指标 (工业级可观测性核心模块).

指标总览 (命名前缀 aiops_):
  - aiops_diagnostic_duration_seconds  Histogram  单次诊断端到端耗时 (MTTR 观测)
  - aiops_diagnostic_total             Counter    诊断完成数, label: status(success/failed)
  - aiops_active_diagnoses             Gauge      当前进行中的诊断数 (并发观测)
  - aiops_token_usage_total            Counter    LLM token 消耗, label: kind(input/output)
  - aiops_tool_calls_total             Counter    工具调用数, label: tool, status(ok/failed/circuit_open)
  - aiops_tool_duration_seconds        Histogram  单工具耗时, label: tool
  - aiops_hitl_pending                 Gauge      等待人工审批的队列长度
  - aiops_hitl_decisions_total         Counter    HITL 审批决定数, label: action(approve/reject)
  - aiops_alerts_received_total        Counter    webhook 收到的 firing 告警数, label: alertname
  - aiops_alerts_deduplicated_total    Counter    去重窗口内被跳过的重复告警数
  - aiops_llm_fallback_total           Counter    LLM 不可用触发规则引擎降级的次数
  - http_requests_total                Counter    HTTP 请求计数, label: method, path_template, status
  - http_request_duration_seconds      Histogram  HTTP 请求耗时

设计原则:
  - 本模块零业务依赖 (只依赖 prometheus_client), 导入无副作用 (仅注册指标)
  - 所有 record_* 都是纯计数/观测函数, 永不抛异常 (可观测性代码不能拖垮业务)
  - 业务代码通过 record_* 函数打点, 不直接触碰 Counter/Histogram 对象
"""

from __future__ import annotations

from typing import Optional

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

# ============================================================
# 指标注册 (模块级单例, prometheus_client 默认 registry)
# ============================================================
DIAGNOSTIC_DURATION = Histogram(
    "aiops_diagnostic_duration_seconds",
    "端到端诊断耗时 (秒), MTTR 核心观测指标",
    buckets=(5, 15, 30, 60, 120, 300, 600, 1800, float("inf")),
)

DIAGNOSTIC_TOTAL = Counter(
    "aiops_diagnostic_total",
    "诊断完成总数",
    ["status"],
)

ACTIVE_DIAGNOSES = Gauge(
    "aiops_active_diagnoses",
    "当前进行中的诊断数量",
)

TOKEN_USAGE = Counter(
    "aiops_token_usage_total",
    "LLM token 累计消耗",
    ["kind"],
)

TOOL_CALLS = Counter(
    "aiops_tool_calls_total",
    "MCP/内置工具调用总数",
    ["tool", "status"],
)

TOOL_DURATION = Histogram(
    "aiops_tool_duration_seconds",
    "单个工具调用耗时 (秒)",
    ["tool"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, float("inf")),
)

HITL_PENDING = Gauge(
    "aiops_hitl_pending",
    "等待人工审批 (HITL) 的队列长度",
)

HITL_DECISIONS = Counter(
    "aiops_hitl_decisions_total",
    "HITL 审批决定计数",
    ["action"],
)

ALERTS_RECEIVED = Counter(
    "aiops_alerts_received_total",
    "webhook 收到的 firing 告警数",
    ["alertname"],
)

ALERTS_DEDUPLICATED = Counter(
    "aiops_alerts_deduplicated_total",
    "去重窗口内跳过的重复告警数",
)

LLM_FALLBACK = Counter(
    "aiops_llm_fallback_total",
    "LLM 不可用触发规则引擎降级的次数",
)

HTTP_REQUESTS = Counter(
    "http_requests_total",
    "HTTP 请求计数 (按路由模板聚合, 非原始 path, 防标签基数爆炸)",
    ["method", "path_template", "status"],
)

HTTP_REQUEST_DURATION = Histogram(
    "http_request_duration_seconds",
    "HTTP 请求耗时 (秒)",
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, float("inf")),
)


# ============================================================
# 打点函数 (业务侧入口, 全部吞异常)
# ============================================================
def record_diagnostic_start() -> None:
    """一次诊断开始: 活跃数 +1."""
    try:
        ACTIVE_DIAGNOSES.inc()
    except Exception:
        pass


def record_diagnostic_end(status: str, duration_sec: float) -> None:
    """一次诊断结束: 活跃数 -1, 计数 + 耗时观测.

    Args:
        status: "success" | "failed"
        duration_sec: 端到端秒数
    """
    try:
        ACTIVE_DIAGNOSES.dec()
        DIAGNOSTIC_TOTAL.labels(status=status).inc()
        if duration_sec >= 0:
            DIAGNOSTIC_DURATION.observe(duration_sec)
    except Exception:
        pass


def record_tokens(input_tokens: int = 0, output_tokens: int = 0) -> None:
    """LLM token 消耗打点 (允许部分为 0)."""
    try:
        if input_tokens:
            TOKEN_USAGE.labels(kind="input").inc(input_tokens)
        if output_tokens:
            TOKEN_USAGE.labels(kind="output").inc(output_tokens)
    except Exception:
        pass


def record_tool_call(tool: str, status: str, duration_sec: Optional[float] = None) -> None:
    """单次工具调用打点.

    Args:
        tool: 工具名 (label 值)
        status: "ok" | "failed" | "circuit_open"
        duration_sec: 耗时; circuit_open 时可为 None (没有真实执行)
    """
    try:
        TOOL_CALLS.labels(tool=tool, status=status).inc()
        if duration_sec is not None and duration_sec >= 0:
            TOOL_DURATION.labels(tool=tool).observe(duration_sec)
    except Exception:
        pass


def record_hitl_pending(delta: int) -> None:
    """HITL 等待队列长度变化 (+1 挂起 / -1 出队)."""
    try:
        HITL_PENDING.inc(delta)
    except Exception:
        pass


def record_hitl_decision(action: str) -> None:
    """HITL 审批决定: approve / reject."""
    try:
        HITL_DECISIONS.labels(action=action).inc()
    except Exception:
        pass


def record_alert_received(alertname: str) -> None:
    try:
        ALERTS_RECEIVED.labels(alertname=alertname).inc()
    except Exception:
        pass


def record_alert_deduplicated() -> None:
    try:
        ALERTS_DEDUPLICATED.inc()
    except Exception:
        pass


def record_llm_fallback() -> None:
    try:
        LLM_FALLBACK.inc()
    except Exception:
        pass


def record_http_request(method: str, path_template: str, status: int, duration_sec: float) -> None:
    """HTTP 请求打点.

    path_template 必须是路由模板 (如 /api/v1/documents/{doc_id}),
    不能是原始 path, 否则高基数标签会拖垮 Prometheus.
    """
    try:
        HTTP_REQUESTS.labels(method=method, path_template=path_template, status=str(status)).inc()
        HTTP_REQUEST_DURATION.observe(duration_sec)
    except Exception:
        pass


def render_metrics() -> bytes:
    """渲染 Prometheus 文本协议格式的指标快照 (供 /metrics 端点)."""
    return generate_latest()


PROMETHEUS_CONTENT_TYPE = CONTENT_TYPE_LATEST
