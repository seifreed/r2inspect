from __future__ import annotations

import time

from r2inspect.utils.rate_limiter import (
    AdaptiveRateLimiter,
    BatchRateLimiter,
    TokenBucket,
    cleanup_memory,
)


def test_token_bucket_acquire_and_timeout() -> None:
    bucket = TokenBucket(capacity=1, refill_rate=0.0)
    assert bucket.acquire(tokens=1, timeout=0.01) is True
    assert bucket.acquire(tokens=1, timeout=0.02) is False


def test_token_bucket_refill() -> None:
    bucket = TokenBucket(capacity=1, refill_rate=10.0)
    bucket.acquire(tokens=1, timeout=0.01)
    time.sleep(0.12)
    assert bucket.acquire(tokens=1, timeout=0.05) is True


def test_adaptive_rate_limiter_adjustments() -> None:
    limiter = AdaptiveRateLimiter(base_rate=5.0, max_rate=10.0, min_rate=1.0)
    limiter.system_check_interval = 0.0
    limiter._check_system_load()
    limiter.record_success()
    limiter.record_success()
    limiter.record_success()
    limiter.record_success()
    limiter.record_success()
    assert limiter.current_rate <= limiter.max_rate
    for _ in range(6):
        limiter.record_error()
    assert limiter.current_rate >= limiter.min_rate
    stats = limiter.get_stats()
    assert "current_rate" in stats
    assert stats["bucket_capacity"] > 0


def test_batch_rate_limiter_stats() -> None:
    limiter = BatchRateLimiter(max_concurrent=1, rate_per_second=100.0, enable_adaptive=False)
    assert limiter.acquire(timeout=0.1) is True
    limiter.release_success()
    assert limiter.acquire(timeout=0.1) is True
    limiter.release_error("fail")
    stats = limiter.get_stats()
    assert stats["files_processed"] == 1
    assert stats["files_failed"] == 1
    assert stats["success_rate"] == 0.5


def test_cleanup_memory_returns_metrics() -> None:
    info = cleanup_memory()
    assert info is None or ("rss_mb" in info and "vms_mb" in info)
