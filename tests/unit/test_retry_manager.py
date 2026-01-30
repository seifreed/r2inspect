import pytest

from r2inspect.utils.retry_manager import RetryConfig, RetryManager, RetryStrategy


def test_retry_operation_succeeds_after_retry():
    manager = RetryManager()
    attempts = {"count": 0}

    def flaky():
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise TimeoutError("temporary")
        return "ok"

    config = RetryConfig(
        max_attempts=2,
        base_delay=0.0,
        max_delay=0.0,
        jitter=False,
        strategy=RetryStrategy.FIXED_DELAY,
    )

    result = manager.retry_operation(flaky, config=config)
    assert result == "ok"
    assert attempts["count"] == 2

    stats = manager.get_stats()
    assert stats["total_retries"] == 1
    assert stats["successful_retries"] == 1


def test_retry_operation_non_retryable_error_propagates():
    manager = RetryManager()
    attempts = {"count": 0}

    def fail():
        attempts["count"] += 1
        raise ValueError("no retry")

    config = RetryConfig(max_attempts=3, base_delay=0.0, jitter=False)

    with pytest.raises(ValueError):
        manager.retry_operation(fail, config=config)

    assert attempts["count"] == 1
    stats = manager.get_stats()
    assert stats["total_retries"] == 0


def test_calculate_delay_linear_backoff_no_jitter():
    manager = RetryManager()
    config = RetryConfig(
        base_delay=0.5,
        max_delay=10.0,
        jitter=False,
        strategy=RetryStrategy.LINEAR_BACKOFF,
    )
    assert manager.calculate_delay(1, config) == 0.5
    assert manager.calculate_delay(2, config) == 1.0
