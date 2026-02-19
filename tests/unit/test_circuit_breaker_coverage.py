#!/usr/bin/env python3
"""
Coverage tests for r2inspect/utils/circuit_breaker.py
"""

import time

import pytest

from r2inspect.utils.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerError,
    CircuitState,
    R2CommandCircuitBreaker,
)


def test_circuit_breaker_closed_to_open_on_failures():
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=60.0, name="test_open")

    def always_fails():
        raise ValueError("fail")

    for _ in range(3):
        with pytest.raises(ValueError):
            cb.call(always_fails)

    assert cb.state == CircuitState.OPEN


def test_circuit_breaker_open_raises_circuit_breaker_error():
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=60.0, name="test_fast_fail")

    def always_fails():
        raise ConnectionError("fail")

    for _ in range(2):
        with pytest.raises(ConnectionError):
            cb.call(always_fails)

    with pytest.raises(CircuitBreakerError):
        cb.call(lambda: "ok")


def test_circuit_breaker_half_open_to_closed_on_success():
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.05, name="test_recovery")

    def always_fails():
        raise OSError("fail")

    for _ in range(2):
        with pytest.raises(OSError):
            cb.call(always_fails)

    assert cb.state == CircuitState.OPEN

    time.sleep(0.1)

    result = cb.call(lambda: "recovered")
    assert result == "recovered"
    assert cb.state == CircuitState.CLOSED


def test_circuit_breaker_half_open_failure_reopens():
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.05, name="test_reopen")

    def always_fails():
        raise OSError("fail")

    for _ in range(2):
        with pytest.raises(OSError):
            cb.call(always_fails)

    time.sleep(0.1)

    with pytest.raises(OSError):
        cb.call(always_fails)

    assert cb.state == CircuitState.OPEN


def test_circuit_breaker_decorator_wraps_function():
    cb = CircuitBreaker(failure_threshold=5, recovery_timeout=60.0, name="test_decorator")

    @cb
    def greet(name):
        return f"hello {name}"

    assert greet("world") == "hello world"


def test_circuit_breaker_get_stats_structure():
    cb = CircuitBreaker(failure_threshold=5, recovery_timeout=60.0, name="stats_test")
    cb.call(lambda: "ok")

    stats = cb.get_stats()
    assert stats["name"] == "stats_test"
    assert stats["state"] == "closed"
    assert stats["total_calls"] == 1
    assert stats["total_successes"] == 1
    assert stats["total_failures"] == 0
    assert stats["success_rate"] == 100.0


def test_circuit_breaker_reset_clears_state():
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=60.0, name="test_reset")

    def always_fails():
        raise ValueError("fail")

    for _ in range(2):
        with pytest.raises(ValueError):
            cb.call(always_fails)

    assert cb.state == CircuitState.OPEN
    cb.reset()
    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0
    assert cb.last_failure_time is None


def test_r2_command_circuit_breaker_get_breaker_analysis_type():
    r2cb = R2CommandCircuitBreaker()
    breaker = r2cb.get_breaker("aaa")
    assert breaker.failure_threshold == 10
    assert breaker.recovery_timeout == 120.0


def test_r2_command_circuit_breaker_get_breaker_search_type():
    r2cb = R2CommandCircuitBreaker()
    breaker = r2cb.get_breaker("/x")
    assert breaker.failure_threshold == 7
    assert breaker.recovery_timeout == 60.0


def test_r2_command_circuit_breaker_get_breaker_generic_type():
    r2cb = R2CommandCircuitBreaker()
    breaker = r2cb.get_breaker("generic_cmd")
    assert breaker.failure_threshold == 5
    assert breaker.recovery_timeout == 30.0


def test_r2_command_circuit_breaker_execute_command_json_success():
    r2cb = R2CommandCircuitBreaker()

    class FakeR2:
        def cmdj(self, cmd):
            return {"result": "ok"}

        def cmd(self, cmd):
            return "ok"

    r2 = FakeR2()
    result = r2cb.execute_command(r2, "isj", command_type="info")
    assert result == {"result": "ok"}


def test_r2_command_circuit_breaker_execute_command_text_success():
    r2cb = R2CommandCircuitBreaker()

    class FakeR2:
        def cmdj(self, cmd):
            return {}

        def cmd(self, cmd):
            return "text output"

    r2 = FakeR2()
    result = r2cb.execute_command(r2, "iz", command_type="info")
    assert result == "text output"


def test_r2_command_circuit_breaker_execute_command_open_circuit_json():
    r2cb = R2CommandCircuitBreaker()
    breaker = r2cb.get_breaker("info")
    breaker.failure_threshold = 1

    class FailR2:
        def cmdj(self, cmd):
            raise RuntimeError("r2 crashed")

        def cmd(self, cmd):
            raise RuntimeError("r2 crashed")

    r2 = FailR2()
    r2cb.execute_command(r2, "isj", command_type="info")

    result = r2cb.execute_command(r2, "isj", command_type="info")
    assert result is None


def test_r2_command_circuit_breaker_execute_command_exception_text():
    r2cb = R2CommandCircuitBreaker()

    class FailR2:
        def cmd(self, cmd):
            raise RuntimeError("fail")

        def cmdj(self, cmd):
            raise RuntimeError("fail")

    r2 = FailR2()
    result = r2cb.execute_command(r2, "iz", command_type="generic")
    assert result == ""


def test_r2_command_circuit_breaker_get_stats_returns_combined():
    r2cb = R2CommandCircuitBreaker()

    class FakeR2:
        def cmd(self, cmd):
            return "ok"

    r2 = FakeR2()
    r2cb.execute_command(r2, "iz", command_type="generic")

    stats = r2cb.get_stats()
    assert "command_generic" in stats
    assert stats["command_generic"]["total_calls"] == 1


def test_r2_command_circuit_breaker_reset_all():
    r2cb = R2CommandCircuitBreaker()

    class FakeR2:
        def cmd(self, cmd):
            return "ok"

    r2 = FakeR2()
    r2cb.execute_command(r2, "iz", command_type="generic")
    r2cb.reset_all()

    assert len(r2cb.command_stats) == 0
