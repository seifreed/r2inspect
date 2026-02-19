#!/usr/bin/env python3
"""Branch-path tests for r2inspect/error_handling/unified_handler.py - real objects only."""

from __future__ import annotations

import time

import pytest

from r2inspect.error_handling.policies import ErrorHandlingStrategy, ErrorPolicy
from r2inspect.error_handling.unified_handler import (
    CircuitBreakerState,
    CircuitState,
    _calculate_retry_delay,
    _circuit_break_execution,
    _fallback_execution,
    _get_circuit_breaker,
    _retry_execution,
    get_circuit_breaker_stats,
    handle_errors,
    reset_circuit_breakers,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_policy(**kwargs) -> ErrorPolicy:
    defaults = {
        "strategy": ErrorHandlingStrategy.CIRCUIT_BREAK,
        "max_retries": 0,
        "retry_delay": 0.0,
        "retry_backoff": 1.0,
        "retry_jitter": False,
        "circuit_threshold": 3,
        "circuit_timeout": 60,
        "fallback_value": None,
    }
    defaults.update(kwargs)
    return ErrorPolicy(**defaults)


def _make_retry_policy(**kwargs) -> ErrorPolicy:
    defaults = {
        "strategy": ErrorHandlingStrategy.RETRY,
        "max_retries": 3,
        "retry_delay": 0.0,
        "retry_backoff": 1.0,
        "retry_jitter": False,
    }
    defaults.update(kwargs)
    return ErrorPolicy(**defaults)


# ---------------------------------------------------------------------------
# CircuitBreakerState.should_allow_request - all branches
# ---------------------------------------------------------------------------


def test_should_allow_request_closed_returns_true():
    cb = CircuitBreakerState(_make_policy())
    assert cb.state == CircuitState.CLOSED
    assert cb.should_allow_request() is True


def test_should_allow_request_open_before_timeout_returns_false():
    cb = CircuitBreakerState(_make_policy(circuit_timeout=9999))
    cb.state = CircuitState.OPEN
    cb.last_failure_time = time.time()
    assert cb.should_allow_request() is False


def test_should_allow_request_open_after_timeout_transitions_to_half_open():
    cb = CircuitBreakerState(_make_policy(circuit_timeout=0))
    cb.state = CircuitState.OPEN
    cb.last_failure_time = time.time() - 1
    result = cb.should_allow_request()
    assert result is True
    assert cb.state == CircuitState.HALF_OPEN


def test_should_allow_request_half_open_returns_true():
    cb = CircuitBreakerState(_make_policy())
    cb.state = CircuitState.HALF_OPEN
    assert cb.should_allow_request() is True


# ---------------------------------------------------------------------------
# CircuitBreakerState.record_success
# ---------------------------------------------------------------------------


def test_record_success_from_half_open_closes_circuit():
    cb = CircuitBreakerState(_make_policy())
    cb.state = CircuitState.HALF_OPEN
    cb.failure_count = 3
    cb.last_failure_time = time.time()
    cb.record_success()
    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0
    assert cb.last_failure_time is None


def test_record_success_from_closed_resets_counters():
    cb = CircuitBreakerState(_make_policy())
    cb.failure_count = 1
    cb.last_failure_time = time.time()
    cb.record_success()
    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0
    assert cb.last_failure_time is None


# ---------------------------------------------------------------------------
# CircuitBreakerState.record_failure
# ---------------------------------------------------------------------------


def test_record_failure_increments_count():
    cb = CircuitBreakerState(_make_policy(circuit_threshold=5))
    cb.record_failure()
    assert cb.failure_count == 1
    assert cb.last_failure_time is not None


def test_record_failure_opens_circuit_at_threshold():
    cb = CircuitBreakerState(_make_policy(circuit_threshold=2))
    cb.record_failure()
    assert cb.state == CircuitState.CLOSED
    cb.record_failure()
    assert cb.state == CircuitState.OPEN


def test_record_failure_above_threshold_stays_open():
    cb = CircuitBreakerState(_make_policy(circuit_threshold=1))
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    assert cb.failure_count == 2


# ---------------------------------------------------------------------------
# CircuitBreakerState._should_attempt_reset
# ---------------------------------------------------------------------------


def test_should_attempt_reset_no_failure_time_returns_false():
    cb = CircuitBreakerState(_make_policy(circuit_timeout=10))
    assert cb._should_attempt_reset() is False


def test_should_attempt_reset_before_timeout_returns_false():
    cb = CircuitBreakerState(_make_policy(circuit_timeout=9999))
    cb.last_failure_time = time.time()
    assert cb._should_attempt_reset() is False


def test_should_attempt_reset_after_timeout_returns_true():
    cb = CircuitBreakerState(_make_policy(circuit_timeout=0))
    cb.last_failure_time = time.time() - 1
    assert cb._should_attempt_reset() is True


# ---------------------------------------------------------------------------
# _calculate_retry_delay
# ---------------------------------------------------------------------------


def test_calculate_retry_delay_attempt_zero():
    policy = _make_retry_policy(retry_delay=2.0, retry_backoff=2.0, retry_jitter=False)
    assert _calculate_retry_delay(0, policy) == 0.0


def test_calculate_retry_delay_attempt_one_equals_base():
    policy = _make_retry_policy(retry_delay=1.0, retry_backoff=2.0, retry_jitter=False)
    assert _calculate_retry_delay(1, policy) == 1.0


def test_calculate_retry_delay_exponential_growth():
    policy = _make_retry_policy(retry_delay=1.0, retry_backoff=2.0, retry_jitter=False)
    assert _calculate_retry_delay(1, policy) == 1.0
    assert _calculate_retry_delay(2, policy) == 2.0
    assert _calculate_retry_delay(3, policy) == 4.0
    assert _calculate_retry_delay(4, policy) == 8.0


def test_calculate_retry_delay_with_jitter_is_positive():
    policy = _make_retry_policy(retry_delay=1.0, retry_backoff=1.0, retry_jitter=True)
    for _ in range(10):
        delay = _calculate_retry_delay(1, policy)
        assert delay > 0


# ---------------------------------------------------------------------------
# _retry_execution - all branches
# ---------------------------------------------------------------------------


def test_retry_execution_immediate_success():
    policy = _make_retry_policy()
    result = _retry_execution(lambda: "ok", policy, (), {})
    assert result == "ok"


def test_retry_execution_success_on_second_attempt():
    attempts = [0]

    def flaky():
        attempts[0] += 1
        if attempts[0] < 2:
            raise ConnectionError("retry me")
        return "success"

    policy = _make_retry_policy(max_retries=3, retry_delay=0.0, retry_jitter=False)
    result = _retry_execution(flaky, policy, (), {})
    assert result == "success"
    assert attempts[0] == 2


def test_retry_execution_non_retryable_raises_immediately():
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.RETRY,
        max_retries=5,
        retry_delay=0.0,
        retry_backoff=1.0,
        retry_jitter=False,
        fatal_exceptions={ValueError},
    )
    attempts = [0]

    def fail():
        attempts[0] += 1
        raise ValueError("fatal")

    with pytest.raises(ValueError):
        _retry_execution(fail, policy, (), {})

    assert attempts[0] == 1  # No retries


def test_retry_execution_exhausts_all_retries():
    attempts = [0]

    def always_fail():
        attempts[0] += 1
        raise ConnectionError("persistent failure")

    policy = _make_retry_policy(max_retries=2, retry_delay=0.0, retry_jitter=False)
    with pytest.raises(ConnectionError):
        _retry_execution(always_fail, policy, (), {})

    assert attempts[0] == 3  # initial + 2 retries


def test_retry_execution_passes_args_and_kwargs():
    def add(a, b, multiplier=1):
        return (a + b) * multiplier

    policy = _make_retry_policy()
    result = _retry_execution(add, policy, (3, 4), {"multiplier": 2})
    assert result == 14


def test_retry_execution_empty_range_raises_runtime_error():
    """Cover the branch where max_retries is forced below 0."""
    policy = _make_retry_policy(max_retries=0)
    policy.max_retries = -1  # bypass __post_init__ validation
    with pytest.raises(RuntimeError, match="Retry execution completed without result"):
        _retry_execution(lambda: "ok", policy, (), {})


def test_retry_execution_logs_success_on_retry(caplog):
    attempts = [0]

    def succeed_on_third():
        attempts[0] += 1
        if attempts[0] < 3:
            raise ConnectionError("fail")
        return "done"

    policy = _make_retry_policy(max_retries=5, retry_delay=0.0, retry_jitter=False)
    result = _retry_execution(succeed_on_third, policy, (), {})
    assert result == "done"


# ---------------------------------------------------------------------------
# _fallback_execution
# ---------------------------------------------------------------------------


def test_fallback_execution_success_returns_result():
    policy = ErrorPolicy(strategy=ErrorHandlingStrategy.FALLBACK, fallback_value="fb")
    result = _fallback_execution(lambda: "real", policy, (), {})
    assert result == "real"


def test_fallback_execution_error_returns_fallback():
    policy = ErrorPolicy(strategy=ErrorHandlingStrategy.FALLBACK, fallback_value="default")

    def broken():
        raise RuntimeError("fail")

    result = _fallback_execution(broken, policy, (), {})
    assert result == "default"


def test_fallback_execution_error_returns_none_fallback():
    policy = ErrorPolicy(strategy=ErrorHandlingStrategy.FALLBACK, fallback_value=None)

    def broken():
        raise RuntimeError("fail")

    result = _fallback_execution(broken, policy, (), {})
    assert result is None


def test_fallback_execution_with_dict_fallback():
    policy = ErrorPolicy(strategy=ErrorHandlingStrategy.FALLBACK, fallback_value={"error": True})

    def broken():
        raise KeyError("missing")

    result = _fallback_execution(broken, policy, (), {})
    assert result == {"error": True}


def test_fallback_execution_passes_args():
    policy = ErrorPolicy(strategy=ErrorHandlingStrategy.FALLBACK, fallback_value=0)
    result = _fallback_execution(lambda a, b: a * b, policy, (3, 5), {})
    assert result == 15


# ---------------------------------------------------------------------------
# _circuit_break_execution
# ---------------------------------------------------------------------------


def test_circuit_break_execution_success_records_and_returns():
    policy = _make_policy(circuit_threshold=5)
    func_id = f"test.circuit.branch.success_{id(object())}"
    result = _circuit_break_execution(lambda: "ok", policy, (), {}, func_id)
    assert result == "ok"
    cb = _get_circuit_breaker(func_id, policy)
    assert cb.failure_count == 0


def test_circuit_break_execution_open_with_fallback_returns_fallback():
    policy = _make_policy(circuit_threshold=1, fallback_value="fallback_val")
    func_id = f"test.circuit.branch.open_fb_{id(object())}"
    cb = _get_circuit_breaker(func_id, policy)
    cb.state = CircuitState.OPEN
    cb.last_failure_time = time.time()

    result = _circuit_break_execution(lambda: "ok", policy, (), {}, func_id)
    assert result == "fallback_val"


def test_circuit_break_execution_open_without_fallback_raises():
    policy = _make_policy(circuit_threshold=1, fallback_value=None)
    func_id = f"test.circuit.branch.open_nofb_{id(object())}"
    cb = _get_circuit_breaker(func_id, policy)
    cb.state = CircuitState.OPEN
    cb.last_failure_time = time.time()

    with pytest.raises(RuntimeError, match="Circuit breaker open"):
        _circuit_break_execution(lambda: "ok", policy, (), {}, func_id)


def test_circuit_break_execution_failure_increments_count():
    policy = _make_policy(circuit_threshold=10)
    func_id = f"test.circuit.branch.fail_{id(object())}"
    cb = _get_circuit_breaker(func_id, policy)
    cb.state = CircuitState.CLOSED
    cb.failure_count = 0

    def broken():
        raise ConnectionError("fail")

    with pytest.raises(ConnectionError):
        _circuit_break_execution(broken, policy, (), {}, func_id)

    assert cb.failure_count >= 1


def test_circuit_break_execution_opens_after_threshold():
    policy = _make_policy(circuit_threshold=2, fallback_value="fb")
    func_id = f"test.circuit.branch.thresh_{id(object())}"
    cb = _get_circuit_breaker(func_id, policy)
    cb.state = CircuitState.CLOSED
    cb.failure_count = 0

    def broken():
        raise ConnectionError("fail")

    for _ in range(2):
        try:
            _circuit_break_execution(broken, policy, (), {}, func_id)
        except ConnectionError:
            pass

    assert cb.state == CircuitState.OPEN


# ---------------------------------------------------------------------------
# handle_errors decorator - all strategies
# ---------------------------------------------------------------------------


def test_handle_errors_fail_fast_success():
    policy = ErrorPolicy(strategy=ErrorHandlingStrategy.FAIL_FAST)

    @handle_errors(policy)
    def good():
        return "ok"

    assert good() == "ok"


def test_handle_errors_fail_fast_propagates_exception():
    policy = ErrorPolicy(strategy=ErrorHandlingStrategy.FAIL_FAST)

    @handle_errors(policy)
    def bad():
        raise ValueError("boom")

    with pytest.raises(ValueError):
        bad()


def test_handle_errors_retry_strategy_success():
    policy = _make_retry_policy(max_retries=2)
    calls = [0]

    @handle_errors(policy)
    def flaky():
        calls[0] += 1
        if calls[0] < 2:
            raise ConnectionError("retry")
        return "done"

    assert flaky() == "done"
    assert calls[0] == 2


def test_handle_errors_fallback_strategy_on_error():
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.FALLBACK,
        fallback_value={"result": "fallback"},
    )

    @handle_errors(policy)
    def broken():
        raise RuntimeError("fail")

    result = broken()
    assert result == {"result": "fallback"}


def test_handle_errors_circuit_break_strategy_success():
    policy = _make_policy(circuit_threshold=5)

    @handle_errors(policy)
    def stable():
        return "stable"

    assert stable() == "stable"


def test_handle_errors_preserves_function_name_and_doc():
    policy = ErrorPolicy(strategy=ErrorHandlingStrategy.FAIL_FAST)

    @handle_errors(policy)
    def documented_function():
        """A documented function."""
        return None

    assert documented_function.__name__ == "documented_function"
    assert documented_function.__doc__ == "A documented function."


def test_handle_errors_passes_args_and_kwargs():
    policy = ErrorPolicy(strategy=ErrorHandlingStrategy.FAIL_FAST)

    @handle_errors(policy)
    def compute(x, y, z=1):
        return x + y + z

    assert compute(2, 3, z=5) == 10


# ---------------------------------------------------------------------------
# reset_circuit_breakers
# ---------------------------------------------------------------------------


def test_reset_circuit_breakers_resets_open_circuit():
    policy = _make_policy(circuit_threshold=1)
    func_id = f"test.reset.branch_{id(object())}"
    cb = _get_circuit_breaker(func_id, policy)
    cb.state = CircuitState.OPEN
    cb.failure_count = 10
    cb.last_failure_time = time.time()

    reset_circuit_breakers()

    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0
    assert cb.last_failure_time is None


def test_reset_circuit_breakers_resets_all():
    policy = _make_policy(circuit_threshold=1)
    ids = [f"test.reset.all_{i}_{id(object())}" for i in range(3)]
    cbs = [_get_circuit_breaker(fid, policy) for fid in ids]
    for cb in cbs:
        cb.state = CircuitState.OPEN
        cb.failure_count = 5

    reset_circuit_breakers()

    for cb in cbs:
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0


# ---------------------------------------------------------------------------
# get_circuit_breaker_stats
# ---------------------------------------------------------------------------


def test_get_circuit_breaker_stats_returns_dict():
    policy = _make_policy(circuit_threshold=3, circuit_timeout=60)
    func_id = f"test.stats.branch_{id(object())}"
    _get_circuit_breaker(func_id, policy)

    stats = get_circuit_breaker_stats()
    assert isinstance(stats, dict)
    assert func_id in stats


def test_get_circuit_breaker_stats_entry_structure():
    policy = _make_policy(circuit_threshold=3, circuit_timeout=60)
    func_id = f"test.stats.struct_{id(object())}"
    cb = _get_circuit_breaker(func_id, policy)
    cb.failure_count = 2
    cb.state = CircuitState.CLOSED

    stats = get_circuit_breaker_stats()
    entry = stats[func_id]
    assert entry["state"] == "closed"
    assert entry["failure_count"] == 2
    assert entry["threshold"] == 3
    assert entry["timeout"] == 60
    assert "last_failure_time" in entry


def test_get_circuit_breaker_stats_open_circuit():
    policy = _make_policy(circuit_threshold=1)
    func_id = f"test.stats.open_{id(object())}"
    cb = _get_circuit_breaker(func_id, policy)
    cb.state = CircuitState.OPEN
    cb.last_failure_time = time.time()

    stats = get_circuit_breaker_stats()
    assert stats[func_id]["state"] == "open"
    assert stats[func_id]["last_failure_time"] is not None
