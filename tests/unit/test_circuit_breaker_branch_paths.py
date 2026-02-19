"""Tests for circuit_breaker.py covering missing branch paths."""

from __future__ import annotations

import threading
import time

import pytest

from r2inspect.utils.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerError,
    CircuitState,
    R2CommandCircuitBreaker,
    r2_circuit_breaker,
)


# ---------------------------------------------------------------------------
# CircuitBreaker.__call__ decorator usage
# ---------------------------------------------------------------------------


def test_call_dunder_used_as_decorator():
    breaker = CircuitBreaker(failure_threshold=3, name="decorator_test")

    @breaker
    def add(x, y):
        return x + y

    assert add(1, 2) == 3
    assert breaker.total_successes == 1


def test_call_dunder_preserves_function_name():
    breaker = CircuitBreaker(failure_threshold=3)

    @breaker
    def my_named_func():
        return 42

    assert my_named_func.__name__ == "my_named_func"


def test_call_dunder_propagates_exception():
    breaker = CircuitBreaker(failure_threshold=5)

    @breaker
    def boom():
        raise ValueError("oops")

    with pytest.raises(ValueError, match="oops"):
        boom()

    assert breaker.total_failures == 1


# ---------------------------------------------------------------------------
# CircuitBreaker.call - OPEN state branches
# ---------------------------------------------------------------------------


def test_call_raises_when_open_and_timeout_not_elapsed():
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=9999.0)

    with pytest.raises(RuntimeError):
        breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("x")))

    assert breaker.state == CircuitState.OPEN

    with pytest.raises(CircuitBreakerError):
        breaker.call(lambda: None)


def test_call_transitions_open_to_half_open_after_timeout():
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=0.0)

    with pytest.raises(RuntimeError):
        breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("x")))

    assert breaker.state == CircuitState.OPEN

    result = breaker.call(lambda: "recovered")
    assert result == "recovered"
    assert breaker.state == CircuitState.CLOSED


def test_call_total_calls_increments():
    breaker = CircuitBreaker(failure_threshold=5)

    breaker.call(lambda: "a")
    breaker.call(lambda: "b")
    assert breaker.total_calls == 2


def test_call_half_open_failure_keeps_open():
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=0.0)

    with pytest.raises(RuntimeError):
        breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("x")))

    assert breaker.state == CircuitState.OPEN

    with pytest.raises(RuntimeError):
        breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("again")))

    assert breaker.state == CircuitState.OPEN


# ---------------------------------------------------------------------------
# CircuitBreaker._on_success - HALF_OPEN -> CLOSED
# ---------------------------------------------------------------------------


def test_on_success_in_half_open_resets_failure_count():
    breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=0.0)

    for _ in range(2):
        with pytest.raises(RuntimeError):
            breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("x")))

    assert breaker.state == CircuitState.OPEN

    breaker.call(lambda: "ok")

    assert breaker.state == CircuitState.CLOSED
    assert breaker.failure_count == 0


def test_on_success_updates_last_success_time():
    breaker = CircuitBreaker(failure_threshold=3)
    before = time.time()
    breaker.call(lambda: "ok")
    assert breaker.last_success_time >= before


# ---------------------------------------------------------------------------
# CircuitBreaker._on_failure - threshold tracking
# ---------------------------------------------------------------------------


def test_on_failure_opens_circuit_at_threshold():
    breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=60.0)

    for _ in range(3):
        with pytest.raises(RuntimeError):
            breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("fail")))

    assert breaker.state == CircuitState.OPEN
    assert breaker.failure_count == 3
    assert breaker.total_failures == 3


def test_on_failure_records_last_failure_time():
    breaker = CircuitBreaker(failure_threshold=5)
    before = time.time()

    with pytest.raises(RuntimeError):
        breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("fail")))

    assert breaker.last_failure_time is not None
    assert breaker.last_failure_time >= before


# ---------------------------------------------------------------------------
# CircuitBreaker._should_attempt_reset
# ---------------------------------------------------------------------------


def test_should_attempt_reset_returns_false_when_no_failure():
    breaker = CircuitBreaker()
    assert breaker._should_attempt_reset() is False


def test_should_attempt_reset_returns_true_after_timeout():
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=0.0)

    with pytest.raises(RuntimeError):
        breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("x")))

    assert breaker._should_attempt_reset() is True


def test_should_attempt_reset_returns_false_before_timeout():
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=9999.0)

    with pytest.raises(RuntimeError):
        breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("x")))

    assert breaker._should_attempt_reset() is False


# ---------------------------------------------------------------------------
# CircuitBreaker._set_state
# ---------------------------------------------------------------------------


def test_set_state_increments_state_changes():
    breaker = CircuitBreaker()
    assert breaker.state_changes == 0

    breaker._set_state(CircuitState.OPEN)
    assert breaker.state_changes == 1

    breaker._set_state(CircuitState.HALF_OPEN)
    assert breaker.state_changes == 2


def test_set_state_no_change_does_not_increment():
    breaker = CircuitBreaker()
    breaker._set_state(CircuitState.CLOSED)
    assert breaker.state_changes == 0


# ---------------------------------------------------------------------------
# CircuitBreaker.reset
# ---------------------------------------------------------------------------


def test_reset_clears_state():
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=60.0)

    with pytest.raises(RuntimeError):
        breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("x")))

    assert breaker.state == CircuitState.OPEN

    breaker.reset()

    assert breaker.state == CircuitState.CLOSED
    assert breaker.failure_count == 0
    assert breaker.last_failure_time is None


# ---------------------------------------------------------------------------
# CircuitBreaker.get_stats
# ---------------------------------------------------------------------------


def test_get_stats_returns_expected_keys():
    breaker = CircuitBreaker(failure_threshold=3, name="stats_test")
    breaker.call(lambda: "ok")

    stats = breaker.get_stats()

    assert stats["name"] == "stats_test"
    assert stats["state"] == "closed"
    assert stats["total_calls"] == 1
    assert stats["total_successes"] == 1
    assert stats["total_failures"] == 0
    assert stats["success_rate"] == 100.0
    assert "failure_count" in stats
    assert "failure_threshold" in stats
    assert "state_changes" in stats


def test_get_stats_success_rate_with_failures():
    breaker = CircuitBreaker(failure_threshold=5)

    breaker.call(lambda: "ok")

    with pytest.raises(RuntimeError):
        breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("x")))

    stats = breaker.get_stats()
    assert stats["total_calls"] == 2
    assert stats["success_rate"] == 50.0


def test_get_stats_no_calls_has_zero_success_rate():
    breaker = CircuitBreaker()
    stats = breaker.get_stats()
    assert stats["total_calls"] == 0
    assert stats["success_rate"] == 0.0


# ---------------------------------------------------------------------------
# CircuitBreaker - expected_exception filtering
# ---------------------------------------------------------------------------


def test_non_expected_exception_does_not_count_as_failure():
    breaker = CircuitBreaker(failure_threshold=2, expected_exception=(ValueError,))

    with pytest.raises(RuntimeError):
        breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("not expected")))

    assert breaker.total_failures == 0
    assert breaker.state == CircuitState.CLOSED


def test_expected_exception_counts_as_failure():
    breaker = CircuitBreaker(failure_threshold=2, expected_exception=(ValueError,))

    with pytest.raises(ValueError):
        breaker.call(lambda: (_ for _ in ()).throw(ValueError("expected")))

    assert breaker.total_failures == 1


# ---------------------------------------------------------------------------
# R2CommandCircuitBreaker.get_breaker - all command type branches
# ---------------------------------------------------------------------------


def test_get_breaker_analysis_commands_have_high_threshold():
    cb = R2CommandCircuitBreaker()

    for cmd in ["analysis", "aaa", "aac", "af"]:
        breaker = cb.get_breaker(cmd)
        assert breaker.failure_threshold == 10
        assert breaker.recovery_timeout == 120.0


def test_get_breaker_search_commands_have_medium_threshold():
    cb = R2CommandCircuitBreaker()

    for cmd in ["search", "/x", "/c"]:
        breaker = cb.get_breaker(cmd)
        assert breaker.failure_threshold == 7
        assert breaker.recovery_timeout == 60.0


def test_get_breaker_generic_commands_have_low_threshold():
    cb = R2CommandCircuitBreaker()

    breaker = cb.get_breaker("generic")
    assert breaker.failure_threshold == 5
    assert breaker.recovery_timeout == 30.0


def test_get_breaker_returns_same_instance_on_second_call():
    cb = R2CommandCircuitBreaker()

    b1 = cb.get_breaker("aaa")
    b2 = cb.get_breaker("aaa")
    assert b1 is b2


def test_get_breaker_creates_distinct_breakers_per_type():
    cb = R2CommandCircuitBreaker()

    b_analysis = cb.get_breaker("analysis")
    b_search = cb.get_breaker("search")
    b_other = cb.get_breaker("other")

    assert b_analysis is not b_search
    assert b_search is not b_other


# ---------------------------------------------------------------------------
# R2CommandCircuitBreaker.execute_command
# ---------------------------------------------------------------------------


class _FakeR2:
    """Minimal r2pipe-like object for testing execute_command."""

    def __init__(self, cmd_return="output", cmdj_return=None, raise_on_cmd=False):
        self._cmd_return = cmd_return
        self._cmdj_return = cmdj_return if cmdj_return is not None else {"key": "val"}
        self._raise_on_cmd = raise_on_cmd

    def cmd(self, command):
        if self._raise_on_cmd:
            raise RuntimeError("cmd failed")
        return self._cmd_return

    def cmdj(self, command):
        if self._raise_on_cmd:
            raise RuntimeError("cmdj failed")
        return self._cmdj_return


def test_execute_command_text_command_returns_string():
    cb = R2CommandCircuitBreaker()
    r2 = _FakeR2(cmd_return="hello")

    result = cb.execute_command(r2, "iz", "generic")
    assert result == "hello"


def test_execute_command_json_command_returns_dict():
    cb = R2CommandCircuitBreaker()
    r2 = _FakeR2(cmdj_return={"sections": []})

    result = cb.execute_command(r2, "ij", "generic")
    assert result == {"sections": []}


def test_execute_command_text_failure_returns_empty_string():
    cb = R2CommandCircuitBreaker()
    r2 = _FakeR2(raise_on_cmd=True)

    result = cb.execute_command(r2, "iz", "generic")
    assert result == ""


def test_execute_command_json_failure_returns_none():
    cb = R2CommandCircuitBreaker()
    r2 = _FakeR2(raise_on_cmd=True)

    result = cb.execute_command(r2, "ij", "generic")
    assert result is None


def test_execute_command_open_circuit_text_returns_empty_string():
    cb = R2CommandCircuitBreaker()
    r2 = _FakeR2(raise_on_cmd=True)

    # Open the circuit
    for _ in range(5):
        cb.execute_command(r2, "iz", "generic")

    # Now circuit should be open - returns empty string fast
    result = cb.execute_command(r2, "iz", "generic")
    assert result == ""


def test_execute_command_open_circuit_json_returns_none():
    cb = R2CommandCircuitBreaker()
    r2 = _FakeR2(raise_on_cmd=True)

    for _ in range(5):
        cb.execute_command(r2, "ij", "generic")

    result = cb.execute_command(r2, "ij", "generic")
    assert result is None


# ---------------------------------------------------------------------------
# R2CommandCircuitBreaker._record_command_stats
# ---------------------------------------------------------------------------


def test_record_command_stats_first_call_sets_avg_time():
    cb = R2CommandCircuitBreaker()
    cb._record_command_stats("test_cmd", True, 0.5)

    stats = cb.command_stats["test_cmd"]
    assert stats["calls"] == 1
    assert stats["failures"] == 0
    assert stats["avg_time"] == 0.5


def test_record_command_stats_failure_increments_failures():
    cb = R2CommandCircuitBreaker()
    cb._record_command_stats("test_cmd", False, 0.1)

    stats = cb.command_stats["test_cmd"]
    assert stats["calls"] == 1
    assert stats["failures"] == 1
    assert len(stats["recent_failures"]) == 1


def test_record_command_stats_moving_average_on_subsequent_calls():
    cb = R2CommandCircuitBreaker()
    cb._record_command_stats("cmd", True, 1.0)
    cb._record_command_stats("cmd", True, 0.0)

    stats = cb.command_stats["cmd"]
    assert stats["calls"] == 2
    # EMA: 0.1 * 0.0 + 0.9 * 1.0 = 0.9
    assert abs(stats["avg_time"] - 0.9) < 1e-9


# ---------------------------------------------------------------------------
# R2CommandCircuitBreaker.get_stats
# ---------------------------------------------------------------------------


def test_r2_circuit_breaker_get_stats_empty():
    cb = R2CommandCircuitBreaker()
    stats = cb.get_stats()
    assert isinstance(stats, dict)


def test_r2_circuit_breaker_get_stats_after_commands():
    cb = R2CommandCircuitBreaker()
    r2 = _FakeR2(cmd_return="data")

    cb.execute_command(r2, "iz", "generic")
    cb.execute_command(r2, "iz", "generic")

    stats = cb.get_stats()
    assert "command_generic" in stats
    cmd_stats = stats["command_generic"]
    assert cmd_stats["total_calls"] == 2
    assert cmd_stats["total_failures"] == 0
    assert cmd_stats["success_rate"] == 100.0


def test_r2_circuit_breaker_get_stats_includes_breaker_stats():
    cb = R2CommandCircuitBreaker()
    r2 = _FakeR2(cmd_return="data")

    cb.execute_command(r2, "iz", "analysis")

    stats = cb.get_stats()
    assert "breaker_analysis" in stats
    assert stats["breaker_analysis"]["state"] == "closed"


def test_r2_circuit_breaker_get_stats_recent_failures():
    cb = R2CommandCircuitBreaker()
    r2 = _FakeR2(raise_on_cmd=True)

    for _ in range(3):
        cb.execute_command(r2, "iz", "generic")

    stats = cb.get_stats()
    assert stats["command_generic"]["total_failures"] == 3
    assert stats["command_generic"]["recent_failures"] >= 0


# ---------------------------------------------------------------------------
# R2CommandCircuitBreaker.reset_all
# ---------------------------------------------------------------------------


def test_reset_all_clears_breakers_and_stats():
    cb = R2CommandCircuitBreaker()
    r2 = _FakeR2(raise_on_cmd=True)

    for _ in range(3):
        cb.execute_command(r2, "iz", "generic")

    cb.reset_all()

    assert len(cb.command_stats) == 0
    for breaker in cb.breakers.values():
        assert breaker.state == CircuitState.CLOSED
        assert breaker.failure_count == 0


# ---------------------------------------------------------------------------
# Global r2_circuit_breaker instance
# ---------------------------------------------------------------------------


def test_global_r2_circuit_breaker_is_r2_command_circuit_breaker():
    assert isinstance(r2_circuit_breaker, R2CommandCircuitBreaker)


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


def test_circuit_breaker_thread_safe_concurrent_calls():
    breaker = CircuitBreaker(failure_threshold=100, name="threaded")
    results = []

    def worker():
        for _ in range(10):
            result = breaker.call(lambda: "ok")
            results.append(result)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 50
    assert breaker.total_calls == 50
    assert breaker.total_successes == 50
