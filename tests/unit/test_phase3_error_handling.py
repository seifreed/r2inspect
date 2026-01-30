from __future__ import annotations

import json

import pytest

from r2inspect.error_handling.policies import ErrorHandlingStrategy, ErrorPolicy
from r2inspect.error_handling.presets import (
    FAIL_FAST_POLICY,
    FALLBACK_LIST_POLICY,
    R2_JSON_DICT_POLICY,
    SAFE_POLICY,
    create_custom_policy,
)
from r2inspect.error_handling.unified_handler import (
    get_circuit_breaker_stats,
    handle_errors,
    reset_circuit_breakers,
)


def test_error_policy_validation() -> None:
    with pytest.raises(ValueError):
        ErrorPolicy(strategy=ErrorHandlingStrategy.RETRY, max_retries=-1)
    with pytest.raises(ValueError):
        ErrorPolicy(strategy=ErrorHandlingStrategy.RETRY, retry_delay=-1.0)
    with pytest.raises(ValueError):
        ErrorPolicy(strategy=ErrorHandlingStrategy.RETRY, retry_backoff=0.5)
    with pytest.raises(ValueError):
        ErrorPolicy(strategy=ErrorHandlingStrategy.RETRY, circuit_threshold=0)
    with pytest.raises(ValueError):
        ErrorPolicy(strategy=ErrorHandlingStrategy.RETRY, circuit_timeout=-1)


def test_error_policy_retryable_and_copy() -> None:
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.RETRY,
        retryable_exceptions={ValueError},
        fatal_exceptions={KeyError},
    )
    assert policy.is_retryable(ValueError("x")) is True
    assert policy.is_retryable(KeyError("x")) is False

    updated = policy.copy_with_overrides(max_retries=10)
    assert updated.max_retries == 10
    with pytest.raises(AttributeError):
        policy.copy_with_overrides(nope=True)


def test_presets_and_custom_policy() -> None:
    assert SAFE_POLICY.fallback_value == {}
    assert isinstance(FALLBACK_LIST_POLICY.fallback_value, list)
    assert FAIL_FAST_POLICY.strategy is ErrorHandlingStrategy.FAIL_FAST
    assert json.JSONDecodeError in R2_JSON_DICT_POLICY.retryable_exceptions

    custom = create_custom_policy(
        ErrorHandlingStrategy.RETRY,
        max_retries=1,
        retry_delay=0.0,
        retry_backoff=1.0,
        retry_jitter=False,
    )
    assert custom.max_retries == 1
    assert custom.retry_delay == 0.0


def test_handle_errors_retry() -> None:
    calls = {"count": 0}
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.RETRY,
        max_retries=1,
        retry_delay=0.0,
        retry_backoff=1.0,
        retry_jitter=False,
        retryable_exceptions={ValueError},
    )

    @handle_errors(policy)
    def flaky():
        calls["count"] += 1
        if calls["count"] < 2:
            raise ValueError("boom")
        return "ok"

    assert flaky() == "ok"
    assert calls["count"] == 2


def test_handle_errors_fallback() -> None:
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.FALLBACK,
        fallback_value=123,
    )

    @handle_errors(policy)
    def always_fail():
        raise RuntimeError("nope")

    assert always_fail() == 123


def test_handle_errors_circuit_breaker() -> None:
    reset_circuit_breakers()
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.CIRCUIT_BREAK,
        max_retries=0,
        retry_delay=0.0,
        retry_backoff=1.0,
        retry_jitter=False,
        circuit_threshold=1,
        circuit_timeout=60,
        fallback_value="fallback",
        retryable_exceptions={ValueError},
    )

    @handle_errors(policy)
    def always_fail():
        raise ValueError("nope")

    with pytest.raises(ValueError):
        always_fail()

    assert always_fail() == "fallback"

    stats = get_circuit_breaker_stats()
    assert stats
