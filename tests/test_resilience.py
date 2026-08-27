"""app/core/resilience.py 熔断器 + app/core/rule_engine.py 规则引擎测试."""

import asyncio

import pytest

from app.core.resilience import (
    CLOSED,
    HALF_OPEN,
    OPEN,
    CircuitBreaker,
    CircuitOpenError,
    get_breaker,
    reset_breakers,
    guarded_call,
)


# ============================================================
# 熔断器状态机
# ============================================================
class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, sec: float) -> None:
        self.t += sec


@pytest.fixture(autouse=True)
def _fresh_registry():
    reset_breakers()
    yield
    reset_breakers()


def _breaker(**kw) -> CircuitBreaker:
    clock = kw.pop("clock", FakeClock())
    return CircuitBreaker("t", failure_threshold=3, recovery_timeout_sec=300, clock=clock, **kw)


class TestCircuitBreakerStateMachine:
    def test_starts_closed(self):
        b = _breaker()
        assert b.state == CLOSED
        assert b.before_call() is True

    def test_opens_after_threshold_failures(self):
        b = _breaker()
        for _ in range(3):
            b.record_failure()
        assert b.state == OPEN
        assert b.before_call() is False

    def test_two_failures_not_enough(self):
        b = _breaker()
        b.record_failure()
        b.record_failure()
        assert b.state == CLOSED  # 未达阈值仍闭路

    def test_success_resets_failures(self):
        b = _breaker()
        b.record_failure()
        b.record_failure()
        b.record_success()
        assert b.state == CLOSED
        assert b.failure_count == 0
        b.record_failure()  # 重新计数, 1 次不开路
        assert b.state == CLOSED

    def test_open_then_half_open_after_timeout(self):
        clock = FakeClock()
        b = CircuitBreaker("t", failure_threshold=3, recovery_timeout_sec=300, clock=clock)
        for _ in range(3):
            b.record_failure()
        assert b.state == OPEN
        clock.advance(299)
        assert b.state == OPEN  # 未到期仍开路
        clock.advance(1.5)
        assert b.state == HALF_OPEN

    def test_half_open_success_closes(self):
        clock = FakeClock()
        b = CircuitBreaker("t", failure_threshold=3, recovery_timeout_sec=300, clock=clock)
        for _ in range(3):
            b.record_failure()
        clock.advance(301)
        assert b.state == HALF_OPEN
        assert b.before_call() is True  # 半开放行探测
        b.record_success()
        assert b.state == CLOSED

    def test_half_open_failure_reopens(self):
        clock = FakeClock()
        b = CircuitBreaker("t", failure_threshold=3, recovery_timeout_sec=300, clock=clock)
        for _ in range(3):
            b.record_failure()
        clock.advance(301)
        b.record_failure()  # 半开态探测失败
        assert b.state == OPEN
        # 且重新计时: 又要等一个完整 recovery 窗口
        clock.advance(299)
        assert b.state == OPEN
        clock.advance(2)
        assert b.state == HALF_OPEN

    def test_check_raises_when_open(self):
        b = _breaker()
        for _ in range(3):
            b.record_failure()
        with pytest.raises(CircuitOpenError) as ei:
            b.check()
        assert "t" in str(ei.value)

    def test_per_tool_isolation(self):
        a = get_breaker("tool_a")
        b = get_breaker("tool_b")
        for _ in range(3):
            a.record_failure()
        assert a.state == OPEN
        assert b.state == CLOSED
        assert b.before_call() is True

    def test_registry_reuses_instance(self):
        assert get_breaker("same_tool") is get_breaker("same_tool")


# ============================================================
# guarded_call
# ============================================================
class TestGuardedCall:
    @pytest.mark.asyncio
    async def test_passthrough_success(self):
        async def ok():
            return 42

        assert await guarded_call("g_ok", ok) == 42
        assert get_breaker("g_ok").state == CLOSED

    @pytest.mark.asyncio
    async def test_passthrough_failure_and_counting(self):
        async def boom():
            raise ValueError("nope")

        with pytest.raises(ValueError):
            await guarded_call("g_bad", boom)
        assert get_breaker("g_bad").failure_count == 1

    @pytest.mark.asyncio
    async def test_open_circuit_short_circuits(self):
        br = get_breaker("g_open")
        for _ in range(3):
            br.record_failure()
        calls = []

        async def never():
            calls.append(1)
            return "should not run"

        with pytest.raises(CircuitOpenError):
            await guarded_call("g_open", never)
        assert calls == []  # coro 从未执行 (fail-fast)


# ============================================================
# 规则引擎
# ============================================================
class TestRuleEngine:
    def test_disk_rule_chinese(self):
        from app.core.rule_engine import rule_engine_diagnose

        md, conf = rule_engine_diagnose("服务器磁盘空间不足, C盘满了")
        assert "磁盘" in md
        assert "df -h" in md
        assert conf >= 0.3

    def test_disk_rule_english(self):
        from app.core.rule_engine import rule_engine_diagnose

        md, conf = rule_engine_diagnose("No space left on device /dev/sda1")
        assert "disk" in md.lower() or "磁盘" in md
        assert conf >= 0.3

    def test_chamber_pressure_semicon_rule(self):
        from app.core.rule_engine import rule_engine_diagnose

        md, conf = rule_engine_diagnose("ETCH-03 反应腔压力异常升高 8.5 Torr")
        assert "chamber" in md.lower() or "反应腔" in md
        assert "throttle valve" in md.lower()
        assert conf >= 0.3

    def test_secs_link_rule(self):
        from app.core.rule_engine import rule_engine_diagnose

        md, _ = rule_engine_diagnose("设备 SECS 通信链路中断, HSMS not selected")
        assert "HSMS" in md or "SECS" in md

    def test_no_match_returns_generic_low_confidence(self):
        from app.core.rule_engine import rule_engine_diagnose

        md, conf = rule_engine_diagnose("随便一句话没有故障词")
        assert "通用" in md
        assert conf == 0.1

    def test_multi_rule_composite_failure(self):
        from app.core.rule_engine import rule_engine_diagnose

        md, conf = rule_engine_diagnose("数据库连接失败且网络丢包超时")
        assert "复合故障" in md
        assert conf >= 0.3

    def test_empty_query_safe(self):
        from app.core.rule_engine import rule_engine_diagnose

        md, conf = rule_engine_diagnose("")
        assert "通用" in md
        assert conf == 0.1

    def test_first_probe(self):
        from app.core.rule_engine import first_probe_for

        assert "磁盘" in first_probe_for("磁盘满了")
        assert first_probe_for("hello world") == ""


# ============================================================
# retry_transient
# ============================================================
class TestRetryTransient:
    @pytest.mark.asyncio
    async def test_retries_on_timeout_then_succeeds(self):
        from app.core.resilience import retry_transient

        attempts = []

        async def flaky():
            attempts.append(1)
            if len(attempts) < 2:
                raise asyncio.TimeoutError()
            return "ok"

        assert await retry_transient(flaky, attempts=3, base_delay=0.01) == "ok"
        assert len(attempts) == 2

    @pytest.mark.asyncio
    async def test_business_error_not_retried(self):
        from app.core.resilience import retry_transient

        attempts = []

        async def bad():
            attempts.append(1)
            raise ValueError("config error")

        with pytest.raises(ValueError):
            await retry_transient(bad, attempts=3, base_delay=0.01)
        assert len(attempts) == 1  # 业务异常立即透传
