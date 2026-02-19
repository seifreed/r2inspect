#!/usr/bin/env python3
"""Coverage tests for r2inspect/error_handling/unified_handler.py"""
from __future__ import annotations

import time

import pytest

from r2inspect.error_handling.policies import ErrorHandlingStrategy, ErrorPolicy
from r2inspect.error_handling.unified_handler import (
    CircuitBreakerState,
    CircuitState,
    _calculate_retry_delay,
    _circuit_break_execution,
    _circuit_breakers,
    _fallback_execution,
    _get_circuit_breaker,
    _retry_execution,
    get_circuit_breaker_stats,
    handle_errors,
    reset_circuit_breakers,
)


# ---------------------------------------------------------------------------
# CircuitState enum
# ---------------------------------------------------------------------------

def test_circuit_state_values():
    assert CircuitState.CLOSED.value == "closed"
    assert CircuitState.OPEN.value == "open"
    assert CircuitState.HALF_OPEN.value == "half_open"


# ---------------------------------------------------------------------------
# CircuitBreakerState
# ---------------------------------------------------------------------------

def _make_policy(**kwargs) -> ErrorPolicy:
    defaults = {
        "strategy": ErrorHandlingStrategy.CIRCUIT_BREAK,
        "max_retries": 0,
        "retry_delay": 0.0,
        "retry_backoff": 1.0,
        "retry_jitter": False,
        "circuit_threshold": 3,
        "circuit_timeout": 1,
        "fallback_value": None,
    }
    defaults.update(kwargs)
    return ErrorPolicy(**defaults)


def test_circuit_breaker_starts_closed():
    policy = _make_policy()
    cb = CircuitBreakerState(policy)
    assert cb.state == CircuitState.CLOSED
    assert cb.should_allow_request() is True


def test_circuit_breaker_opens_after_threshold_failures():
    policy = _make_policy(circuit_threshold=2)
    cb = CircuitBreakerState(policy)
    cb.record_failure()
    assert cb.state == CircuitState.CLOSED
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    assert cb.should_allow_request() is False


def test_circuit_breaker_transitions_to_half_open_after_timeout():
    policy = _make_policy(circuit_threshold=1, circuit_timeout=0)
    cb = CircuitBreakerState(policy)
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    # With timeout=0 the reset check should pass immediately
    cb.last_failure_time = time.time() - 1
    assert cb.should_allow_request() is True
    assert cb.state == CircuitState.HALF_OPEN


def test_circuit_breaker_half_open_allows_request():
    policy = _make_policy()
    cb = CircuitBreakerState(policy)
    cb.state = CircuitState.HALF_OPEN
    assert cb.should_allow_request() is True


def test_circuit_breaker_record_success_from_half_open_closes_circuit():
    policy = _make_policy()
    cb = CircuitBreakerState(policy)
    cb.state = CircuitState.HALF_OPEN
    cb.failure_count = 2
    cb.record_success()
    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0
    assert cb.last_failure_time is None


def test_circuit_breaker_record_success_from_closed_resets_count():
    policy = _make_policy()
    cb = CircuitBreakerState(policy)
    cb.failure_count = 1
    cb.record_success()
    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0


def test_circuit_breaker_should_attempt_reset_no_failure_time():
    policy = _make_policy(circuit_timeout=60)
    cb = CircuitBreakerState(policy)
    assert cb._should_attempt_reset() is False


def test_circuit_breaker_should_not_attempt_reset_before_timeout():
    policy = _make_policy(circuit_timeout=60)
    cb = CircuitBreakerState(policy)
    cb.last_failure_time = time.time()
    assert cb._should_attempt_reset() is False


# ---------------------------------------------------------------------------
# _get_circuit_breaker
# ---------------------------------------------------------------------------

def test_get_circuit_breaker_creates_and_reuses():
    policy = _make_policy()
    cb1 = _get_circuit_breaker("test.module.func_unique_1", policy)
    cb2 = _get_circuit_breaker("test.module.func_unique_1", policy)
    assert cb1 is cb2


def test_get_circuit_breaker_different_keys_different_instances():
    policy = _make_policy()
    cb1 = _get_circuit_breaker("test.module.funcA", policy)
    cb2 = _get_circuit_breaker("test.module.funcB", policy)
    assert cb1 is not cb2


# ---------------------------------------------------------------------------
# _calculate_retry_delay
# ---------------------------------------------------------------------------

def test_calculate_retry_delay_attempt_zero_is_zero():
    policy = _make_policy(retry_delay=1.0, retry_backoff=2.0, retry_jitter=False)
    assert _calculate_retry_delay(0, policy) == 0.0


def test_calculate_retry_delay_first_attempt_equals_base_delay():
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.RETRY,
        retry_delay=1.0,
        retry_backoff=2.0,
        retry_jitter=False,
        max_retries=3,
    )
    delay = _calculate_retry_delay(1, policy)
    assert delay == 1.0


def test_calculate_retry_delay_exponential_backoff():
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.RETRY,
        retry_delay=1.0,
        retry_backoff=2.0,
        retry_jitter=False,
        max_retries=5,
    )
    assert _calculate_retry_delay(1, policy) == 1.0
    assert _calculate_retry_delay(2, policy) == 2.0
    assert _calculate_retry_delay(3, policy) == 4.0


def test_calculate_retry_delay_with_jitter_is_positive():
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.RETRY,
        retry_delay=1.0,
        retry_backoff=1.0,
        retry_jitter=True,
        max_retries=3,
    )
    delay = _calculate_retry_delay(1, policy)
    assert delay > 0


# ---------------------------------------------------------------------------
# _retry_execution
# ---------------------------------------------------------------------------

def test_retry_execution_success_first_attempt():
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.RETRY,
        max_retries=3,
        retry_delay=0.0,
        retry_backoff=1.0,
        retry_jitter=False,
    )
    result = _retry_execution(lambda: "ok", policy, (), {})
    assert result == "ok"


def test_retry_execution_succeeds_after_retries():
    call_count = [0]

    def flaky():
        call_count[0] += 1
        if call_count[0] < 3:
            raise ConnectionError("retry me")
        return "done"

    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.RETRY,
        max_retries=5,
        retry_delay=0.0,
        retry_backoff=1.0,
        retry_jitter=False,
    )
    result = _retry_execution(flaky, policy, (), {})
    assert result == "done"
    assert call_count[0] == 3


def test_retry_execution_raises_non_retryable_error():
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.RETRY,
        max_retries=3,
        retry_delay=0.0,
        retry_backoff=1.0,
        retry_jitter=False,
        fatal_exceptions={ValueError},
    )

    def fail():
        raise ValueError("fatal")

    with pytest.raises(ValueError):
        _retry_execution(fail, policy, (), {})


def test_retry_execution_exhausts_all_retries():
    attempts = [0]

    def always_fail():
        attempts[0] += 1
        raise ConnectionError("always fails")

    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.RETRY,
        max_retries=2,
        retry_delay=0.0,
        retry_backoff=1.0,
        retry_jitter=False,
    )

    with pytest.raises(ConnectionError):
        _retry_execution(always_fail, policy, (), {})

    assert attempts[0] == 3  # initial + 2 retries


# ---------------------------------------------------------------------------
# _fallback_execution
# ---------------------------------------------------------------------------

def test_fallback_execution_success_returns_result():
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.FALLBACK,
        fallback_value="fallback",
    )
    result = _fallback_execution(lambda: "ok", policy, (), {})
    assert result == "ok"


def test_fallback_execution_error_returns_fallback():
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.FALLBACK,
        fallback_value="default",
    )

    def broken():
        raise RuntimeError("fail")

    result = _fallback_execution(broken, policy, (), {})
    assert result == "default"


def test_fallback_execution_with_args():
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.FALLBACK,
        fallback_value=0,
    )
    result = _fallback_execution(lambda a, b: a + b, policy, (3, 4), {})
    assert result == 7


# ---------------------------------------------------------------------------
# _circuit_break_execution
# ---------------------------------------------------------------------------

def test_circuit_break_execution_success():
    policy = _make_policy(circuit_threshold=5)
    func_id = "test.circuit.success_func"
    # Reset circuit breaker to clean state
    cb = _get_circuit_breaker(func_id, policy)
    cb.state = CircuitState.CLOSED
    cb.failure_count = 0

    result = _circuit_break_execution(lambda: "ok", policy, (), {}, func_id)
    assert result == "ok"


def test_circuit_break_execution_open_circuit_returns_fallback():
    policy = _make_policy(circuit_threshold=1, fallback_value="fb")
    func_id = "test.circuit.open_func"
    cb = _get_circuit_breaker(func_id, policy)
    cb.state = CircuitState.OPEN
    cb.last_failure_time = time.time()  # prevent reset

    result = _circuit_break_execution(lambda: "ok", policy, (), {}, func_id)
    assert result == "fb"


def test_circuit_break_execution_open_circuit_no_fallback_raises():
    policy = _make_policy(circuit_threshold=1, fallback_value=None)
    func_id = "test.circuit.open_no_fallback"
    cb = _get_circuit_breaker(func_id, policy)
    cb.state = CircuitState.OPEN
    cb.last_failure_time = time.time()

    with pytest.raises(RuntimeError, match="Circuit breaker open"):
        _circuit_break_execution(lambda: "ok", policy, (), {}, func_id)


def test_circuit_break_execution_failure_records_and_raises():
    policy = _make_policy(circuit_threshold=10)
    func_id = "test.circuit.fail_func"
    cb = _get_circuit_breaker(func_id, policy)
    cb.state = CircuitState.CLOSED
    cb.failure_count = 0

    def broken():
        raise ConnectionError("conn fail")

    with pytest.raises(ConnectionError):
        _circuit_break_execution(broken, policy, (), {}, func_id)

    assert cb.failure_count >= 1


# ---------------------------------------------------------------------------
# handle_errors decorator
# ---------------------------------------------------------------------------

def test_handle_errors_fail_fast_success():
    policy = ErrorPolicy(strategy=ErrorHandlingStrategy.FAIL_FAST)

    @handle_errors(policy)
    def my_func():
        return "success"

    assert my_func() == "success"


def test_handle_errors_fail_fast_raises_on_error():
    policy = ErrorPolicy(strategy=ErrorHandlingStrategy.FAIL_FAST)

    @handle_errors(policy)
    def my_func():
        raise ValueError("fail")

    with pytest.raises(ValueError):
        my_func()


def test_handle_errors_retry_strategy():
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.RETRY,
        max_retries=2,
        retry_delay=0.0,
        retry_backoff=1.0,
        retry_jitter=False,
    )
    calls = [0]

    @handle_errors(policy)
    def flaky_func():
        calls[0] += 1
        if calls[0] < 2:
            raise ConnectionError("retry")
        return "ok"

    result = flaky_func()
    assert result == "ok"


def test_handle_errors_fallback_strategy():
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.FALLBACK,
        fallback_value="fb_value",
    )

    @handle_errors(policy)
    def broken_func():
        raise RuntimeError("broken")

    assert broken_func() == "fb_value"


def test_handle_errors_circuit_break_strategy():
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.CIRCUIT_BREAK,
        max_retries=0,
        retry_delay=0.0,
        retry_backoff=1.0,
        retry_jitter=False,
        circuit_threshold=10,
        circuit_timeout=60,
        fallback_value=None,
    )

    @handle_errors(policy)
    def stable_func():
        return "stable"

    assert stable_func() == "stable"


def test_handle_errors_preserves_function_name():
    policy = ErrorPolicy(strategy=ErrorHandlingStrategy.FAIL_FAST)

    @handle_errors(policy)
    def uniquely_named_function():
        return None

    assert uniquely_named_function.__name__ == "uniquely_named_function"


# ---------------------------------------------------------------------------
# reset_circuit_breakers / get_circuit_breaker_stats
# ---------------------------------------------------------------------------

def test_reset_circuit_breakers_clears_open_circuits():
    policy = _make_policy(circuit_threshold=1)
    cb = _get_circuit_breaker("test.reset.func", policy)
    cb.state = CircuitState.OPEN
    cb.failure_count = 5

    reset_circuit_breakers()

    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0
    assert cb.last_failure_time is None


def test_get_circuit_breaker_stats_returns_dict():
    policy = _make_policy()
    _get_circuit_breaker("test.stats.func", policy)

    stats = get_circuit_breaker_stats()
    assert isinstance(stats, dict)
    assert "test.stats.func" in stats
    entry = stats["test.stats.func"]
    assert "state" in entry
    assert "failure_count" in entry
    assert "threshold" in entry
    assert "timeout" in entry


# ---------------------------------------------------------------------------
# _retry_execution edge case: max_retries=-1 covers lines 175-177
# ---------------------------------------------------------------------------

def test_retry_execution_with_negative_max_retries_raises_runtime_error():
    """Cover lines 175-177: loop never runs when max_retries is forced to -1."""
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.RETRY,
        max_retries=0,
        retry_delay=0.0,
        retry_backoff=1.0,
        retry_jitter=False,
    )
    # Bypass post_init validation to force unreachable path
    policy.max_retries = -1
    # range(-1 + 1) == range(0) -> empty loop -> reaches "if last_exception" branch
    with pytest.raises(RuntimeError, match="Retry execution completed without result"):
        _retry_execution(lambda: "ok", policy, (), {})


# ---------------------------------------------------------------------------
# handle_errors assert_never branch (lines 285-286)
# ---------------------------------------------------------------------------

def test_handle_errors_assert_never_with_invalid_strategy():
    """Cover lines 285-286: assert_never branch for unknown strategy."""
    from r2inspect.error_handling.policies import ErrorPolicy, ErrorHandlingStrategy

    # Create a policy with a valid strategy but override it to an invalid value
    policy = ErrorPolicy(strategy=ErrorHandlingStrategy.FAIL_FAST)
    # Force an invalid strategy value to hit the assert_never branch
    policy.strategy = "not_a_real_strategy"

    @handle_errors(policy)
    def my_func():
        return "ok"

    import pytest
    with pytest.raises((AssertionError, Exception)):
        my_func()
