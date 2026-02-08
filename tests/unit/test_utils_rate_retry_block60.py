from __future__ import annotations

import time

import pytest

from r2inspect.utils.rate_limiter import AdaptiveRateLimiter, BatchRateLimiter, TokenBucket
from r2inspect.utils.retry_manager import RetryConfig, RetryManager, RetryStrategy


def test_token_bucket_basic():
    bucket = TokenBucket(capacity=1, refill_rate=0)
    assert bucket.acquire(tokens=1, timeout=0.1) is True
    # No refill, should timeout
    assert bucket.acquire(tokens=1, timeout=0.01) is False


def test_adaptive_rate_limiter_stats():
    limiter = AdaptiveRateLimiter(base_rate=1.0, max_rate=2.0, min_rate=0.5)
    limiter.system_check_interval = 0.0
    assert limiter.acquire_permit(timeout=0.1) in {True, False}
    limiter.record_success()
    limiter.record_error("fail")
    stats = limiter.get_stats()
    assert "current_rate" in stats


def test_batch_rate_limiter():
    limiter = BatchRateLimiter(max_concurrent=1, rate_per_second=10.0, burst_size=1)
    assert limiter.acquire(timeout=0.1) is True
    limiter.release_success()
    assert limiter.acquire(timeout=0.1) is True
    limiter.release_error("err")
    stats = limiter.get_stats()
    assert stats["files_processed"] >= 1


def test_retry_manager_success_after_retry():
    manager = RetryManager()
    attempts = {"count": 0}

    def flaky(**_kwargs):
        attempts["count"] += 1
        if attempts["count"] < 2:
            raise TimeoutError("timeout")
        return "ok"

    config = RetryConfig(
        max_attempts=2, base_delay=0.0, jitter=False, strategy=RetryStrategy.FIXED_DELAY
    )
    result = manager.retry_operation(flaky, command="iij", config=config)
    assert result == "ok"

    stats = manager.get_stats()
    assert stats["total_retries"] >= 1


def test_retry_manager_non_retryable_error():
    manager = RetryManager()

    def bad(**_kwargs):
        raise ValueError("nope")

    config = RetryConfig(
        max_attempts=1, base_delay=0.0, jitter=False, strategy=RetryStrategy.FIXED_DELAY
    )
    with pytest.raises(ValueError):
        manager.retry_operation(bad, command="foo", config=config)
