from __future__ import annotations

import time

import pytest

from r2inspect.utils.retry_manager import (
    RetryableError,
    RetryConfig,
    RetryManager,
    RetryStrategy,
    retry_on_failure,
    retry_r2_operation,
)


def test_retry_manager_basic_flow() -> None:
    manager = RetryManager()
    attempts = {"count": 0}

    def flaky() -> str:
        attempts["count"] += 1
        if attempts["count"] < 2:
            raise RetryableError("try again")
        return "ok"

    config = RetryConfig(
        max_attempts=2, base_delay=0.0, jitter=False, strategy=RetryStrategy.FIXED_DELAY
    )
    assert manager.retry_operation(flaky, config=config) == "ok"
    stats = manager.get_stats()
    assert stats["total_retries"] == 1
    assert stats["successful_retries"] == 1


def test_retry_manager_non_retryable_error() -> None:
    manager = RetryManager()

    def boom() -> None:
        raise ValueError("no retry")

    config = RetryConfig(max_attempts=2, base_delay=0.0, jitter=False)
    with pytest.raises(ValueError):
        manager.retry_operation(boom, config=config)


def test_retry_manager_timeout() -> None:
    manager = RetryManager()

    def slow_fail() -> None:
        time.sleep(0.01)
        raise RetryableError("timeout")

    config = RetryConfig(max_attempts=2, base_delay=0.0, jitter=False, timeout=0.001)
    with pytest.raises(TimeoutError):
        manager.retry_operation(slow_fail, config=config)


def test_retry_manager_calculate_delay_strategies() -> None:
    manager = RetryManager()
    fixed = RetryConfig(base_delay=0.2, jitter=False, strategy=RetryStrategy.FIXED_DELAY)
    exp = RetryConfig(base_delay=0.2, jitter=False, strategy=RetryStrategy.EXPONENTIAL_BACKOFF)
    linear = RetryConfig(base_delay=0.2, jitter=False, strategy=RetryStrategy.LINEAR_BACKOFF)
    jitter = RetryConfig(base_delay=0.2, jitter=False, strategy=RetryStrategy.RANDOM_JITTER)

    assert manager.calculate_delay(2, fixed) == pytest.approx(0.2)
    assert manager.calculate_delay(2, exp) == pytest.approx(0.4)
    assert manager.calculate_delay(3, linear) == pytest.approx(0.6)
    assert 0.2 <= manager.calculate_delay(1, jitter) <= jitter.max_delay


def test_retry_on_failure_decorator_and_retry_r2_operation() -> None:
    attempts = {"count": 0}

    @retry_on_failure(
        command_type="generic",
        config=RetryConfig(max_attempts=2, base_delay=0.0, jitter=False),
        auto_retry=False,
    )
    def flaky_call(*_args: object, **_kwargs: object) -> str:
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise RetryableError("try again")
        return "ij"

    assert flaky_call(object(), "ij") == "ij"

    attempts = {"count": 0}

    def op(command: str) -> str:
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise RetryableError("try again")
        return command

    assert retry_r2_operation(op, "ij") == "ij"
