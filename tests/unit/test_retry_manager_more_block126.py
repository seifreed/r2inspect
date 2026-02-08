from __future__ import annotations

import pytest

from r2inspect.utils.retry_manager import RetryConfig, RetryManager, RetryStrategy


def test_retry_manager_retries_then_succeeds():
    manager = RetryManager()
    config = RetryConfig(
        max_attempts=3, base_delay=0.0, jitter=False, strategy=RetryStrategy.FIXED_DELAY
    )

    state = {"count": 0}

    def flaky(**_kwargs):
        state["count"] += 1
        if state["count"] < 2:
            raise ConnectionError("connection reset")
        return "ok"

    result = manager.retry_operation(flaky, command_type="generic", config=config, command="iij")
    assert result == "ok"

    stats = manager.get_stats()
    assert stats["total_retries"] == 1
    assert stats["successful_retries"] == 1


def test_retry_manager_non_retryable_error_raises():
    manager = RetryManager()
    config = RetryConfig(
        max_attempts=2, base_delay=0.0, jitter=False, strategy=RetryStrategy.FIXED_DELAY
    )

    def bad():
        raise ValueError("no retry")

    with pytest.raises(ValueError):
        manager.retry_operation(bad, command_type="generic", config=config)
