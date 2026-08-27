"""工具调用熔断器 (Circuit Breaker) — 工业级容错核心模块.

为什么需要:
  一个 MCP 探针 (如某台网络设备) 卡死时, 每次调用要挂满超时 (10-30s),
  并发扇出的专家 Agent 会集体阻塞在线程池上, 把「单点故障」放大成
  「全局雪崩」。熔断器在连续失败 N 次后直接快速失败 (fail-fast),
  冷却期内完全跳过该工具, 半开态放一个探测请求验证恢复。

状态机 (三态):
  CLOSED ──连续 failure_threshold 次失败──► OPEN
     ▲                                      │ recovery_timeout_sec 到期
     │ record_success                       ▼
     └──────────────────────────────── HALF_OPEN
                                             │ record_failure
                                             └──► OPEN (重新计时)

用法:
    breaker = get_breaker("network_ping")        # per-tool 独立熔断器
    async with breaker guard:                    # 或用便捷封装
        result = await guarded_call("network_ping", lambda: tool.ainvoke(args))

配置 (环境变量, 不依赖 app/config.py, 便于独立演进):
  AIOPS_CB_FAILURE_THRESHOLD  连续失败阈值, 默认 3
  AIOPS_CB_RECOVERY_SEC       OPEN → HALF_OPEN 冷却秒数, 默认 300 (5min)

设计:
  - 线程安全 (threading.Lock): LangGraph 节点可能跑在线程池
  - clock 可注入 (默认 time.monotonic): 单测不需真实等待
  - 零第三方依赖 (不用 pybreaker: 其 async 支持弱且全局单例难做 per-tool 隔离)
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from typing import Any, Awaitable, Callable, Dict, Optional

from loguru import logger


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return default


# 默认参数 (环境变量可覆盖)
DEFAULT_FAILURE_THRESHOLD = _env_int("AIOPS_CB_FAILURE_THRESHOLD", 3)
DEFAULT_RECOVERY_SEC = _env_int("AIOPS_CB_RECOVERY_SEC", 300)

# 状态常量 (字符串, 便于日志/指标/测试断言)
CLOSED = "closed"
OPEN = "open"
HALF_OPEN = "half_open"


class CircuitOpenError(RuntimeError):
    """熔断器开路时抛出 (调用方应跳过该工具而不是等待)."""

    def __init__(self, tool: str, retry_after_sec: float):
        self.tool = tool
        self.retry_after_sec = retry_after_sec
        super().__init__(
            f"circuit open for tool {tool!r}, retry after {retry_after_sec:.0f}s"
        )


class CircuitBreaker:
    """单个工具的熔断器 (per-tool 实例, 由 get_breaker registry 管理)."""

    def __init__(
        self,
        name: str,
        *,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        recovery_timeout_sec: float = DEFAULT_RECOVERY_SEC,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.name = name
        self.failure_threshold = max(1, failure_threshold)
        self.recovery_timeout_sec = max(0.0, recovery_timeout_sec)
        self._clock = clock
        self._lock = threading.Lock()
        self._state = CLOSED
        self._failure_count = 0
        self._opened_at = 0.0  # monotonic 时间戳

    # ============================================================
    # 状态查询
    # ============================================================
    @property
    def state(self) -> str:
        with self._lock:
            return self._effective_state()

    def _effective_state(self) -> str:
        """调用方必须已持有 self._lock."""
        if self._state == OPEN:
            if self._clock() - self._opened_at >= self.recovery_timeout_sec:
                return HALF_OPEN
        return self._state

    @property
    def failure_count(self) -> int:
        with self._lock:
            return self._failure_count

    def _retry_after(self) -> float:
        """OPEN 状态下距离 HALF_OPEN 的剩余秒数."""
        elapsed = self._clock() - self._opened_at
        return max(0.0, self.recovery_timeout_sec - elapsed)

    # ============================================================
    # 状态转移
    # ============================================================
    def _trip_open(self) -> None:
        """调用方必须已持有 self._lock."""
        self._state = OPEN
        self._opened_at = self._clock()
        self._failure_count = 0
        logger.warning(
            f"[CircuitBreaker] {self.name}: CLOSED/OPEN → OPEN "
            f"(threshold={self.failure_threshold}, recovery={self.recovery_timeout_sec}s)"
        )

    def record_failure(self) -> None:
        with self._lock:
            state = self._effective_state()
            if state == HALF_OPEN:
                # 半开态探测失败: 立即重新熔断
                self._trip_open()
                return
            self._failure_count += 1
            if self._failure_count >= self.failure_threshold:
                self._trip_open()

    def record_success(self) -> None:
        with self._lock:
            if self._state != CLOSED:
                logger.info(f"[CircuitBreaker] {self.name}: {self._state} → CLOSED (probe succeeded)")
            self._state = CLOSED
            self._failure_count = 0

    # ============================================================
    # 调用前检查
    # ============================================================
    def before_call(self) -> bool:
        """是否放行本次调用.

        Returns:
            True  放行 (CLOSED, 或 HALF_OPEN 的探测请求)
            False 拒绝 (OPEN)
        """
        with self._lock:
            state = self._effective_state()
            if state == OPEN:
                return False
            if state == HALF_OPEN:
                # 半开态只放一个探测请求: 状态保持 HALF_OPEN,
                # 由 record_success / record_failure 决定归宿
                return True
            return True

    # ============================================================
    # 便捷断言 (抛异常风格)
    # ============================================================
    def check(self) -> None:
        """开路时抛 CircuitOpenError, 闭路/半开直接返回."""
        with self._lock:
            state = self._effective_state()
            if state == OPEN:
                raise CircuitOpenError(self.name, self._retry_after())


# ============================================================
# Registry: per-tool 隔离
# ============================================================
_registry: Dict[str, CircuitBreaker] = {}
_registry_lock = threading.Lock()


def get_breaker(name: str, **overrides: Any) -> CircuitBreaker:
    """按工具名取/建熔断器 (同名复用同一实例).

    overrides 仅在首次创建时生效 (测试可用注入 clock/failure_threshold).
    """
    with _registry_lock:
        if name not in _registry:
            _registry[name] = CircuitBreaker(name, **overrides)
        return _registry[name]


def reset_breakers() -> None:
    """清空 registry (仅测试用)."""
    with _registry_lock:
        _registry.clear()


def breaker_states() -> Dict[str, str]:
    """当前所有熔断器状态快照 (观测/调试用)."""
    with _registry_lock:
        return {name: b.state for name, b in _registry.items()}


# ============================================================
# 便捷调用封装
# ============================================================
async def guarded_call(
    name: str,
    coro_factory: Callable[[], Awaitable[Any]],
) -> Any:
    """带熔断保护的异步调用.

    Args:
        name: 工具名 (熔断器粒度)
        coro_factory: 零参工厂, 每次调用产出新协程 (重试安全)

    Raises:
        CircuitOpenError: 熔断开路
        其他: 原样透传 coro 的异常 (已计入 failure)
    """
    breaker = get_breaker(name)
    breaker.check()  # 开路直接抛, 不执行 coro
    try:
        result = await coro_factory()
    except CircuitOpenError:
        raise
    except BaseException as exc:  # noqa: BLE001 — 失败计数必须覆盖所有异常路径
        breaker.record_failure()
        raise exc
    breaker.record_success()
    return result


async def retry_transient(
    coro_factory: Callable[[], Awaitable[Any]],
    *,
    attempts: int = 2,
    base_delay: float = 0.5,
) -> Any:
    """瞬时错误重试 (指数退避 + 抖动).

    只重试网络瞬时类异常 (TimeoutError/ConnectionError/asyncio.TimeoutError),
    业务异常 (ValueError 等) 立即透传 —— 重试没有意义.

    不引入 tenacity 运行时依赖的考量: 逻辑极简 (两行退避), 自带实现
    可控可测, 避免「为重试引一个全家桶」.
    """
    transient = (TimeoutError, ConnectionError, asyncio.TimeoutError)
    last_exc: Optional[BaseException] = None
    for attempt in range(max(1, attempts)):
        try:
            return await coro_factory()
        except transient as exc:
            last_exc = exc
            if attempt == attempts - 1:
                raise
            # 指数退避: base * 2^n + 全抖动 (full jitter)
            delay = base_delay * (2 ** attempt)
            delay = delay / 2 + (time.time() % 1) * delay / 2
            logger.debug(f"[retry_transient] attempt {attempt + 1} failed ({exc!r}), retrying in {delay:.2f}s")
            await asyncio.sleep(delay)
        except BaseException:
            raise
    assert last_exc is not None
    raise last_exc
