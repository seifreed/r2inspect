from __future__ import annotations

import time

from r2inspect.utils.rate_limiter import AdaptiveRateLimiter, BatchRateLimiter, TokenBucket


def test_token_bucket_timeout_and_acquire():
    bucket = TokenBucket(capacity=1, refill_rate=0.0)
    assert bucket.acquire(timeout=0.01) is True
    # no refill, should time out
    assert bucket.acquire(timeout=0.05) is False


def test_adaptive_rate_limiter_stats_and_adjustment():
    limiter = AdaptiveRateLimiter(base_rate=1.0, max_rate=2.0, min_rate=0.5)

    for _ in range(6):
        limiter.record_success()
    stats = limiter.get_stats()
    assert "current_rate" in stats
    assert stats["current_rate"] <= limiter.max_rate

    for _ in range(6):
        limiter.record_error("err")
    stats = limiter.get_stats()
    assert stats["current_rate"] >= limiter.min_rate


def test_batch_rate_limiter_basic_stats():
    limiter = BatchRateLimiter(
        max_concurrent=1, rate_per_second=100.0, burst_size=5, enable_adaptive=False
    )

    assert limiter.acquire(timeout=0.1) is True
    limiter.release_success()

    assert limiter.acquire(timeout=0.1) is True
    limiter.release_error("fail")

    stats = limiter.get_stats()
    assert stats["files_processed"] == 1
    assert stats["files_failed"] == 1
    assert 0.0 <= stats["success_rate"] <= 1.0
