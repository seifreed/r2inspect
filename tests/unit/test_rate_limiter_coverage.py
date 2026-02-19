#!/usr/bin/env python3
"""
Coverage tests for r2inspect/utils/rate_limiter.py
"""

import time

import pytest

from r2inspect.utils.rate_limiter import (
    AdaptiveRateLimiter,
    BatchRateLimiter,
    TokenBucket,
    cleanup_memory,
)


def test_token_bucket_basic_acquire():
    bucket = TokenBucket(capacity=10, refill_rate=100.0)
    assert bucket.acquire(tokens=1) is True


def test_token_bucket_exhausts_and_refills():
    bucket = TokenBucket(capacity=2, refill_rate=50.0)
    assert bucket.acquire(tokens=1, timeout=0.05) is True
    assert bucket.acquire(tokens=1, timeout=0.05) is True
    assert bucket.acquire(tokens=1, timeout=0.01) is False
    time.sleep(0.03)
    assert bucket.acquire(tokens=1, timeout=0.1) is True


def test_token_bucket_no_timeout_acquires_eventually():
    bucket = TokenBucket(capacity=1, refill_rate=100.0)
    assert bucket.acquire(tokens=1) is True
    assert bucket.acquire(tokens=1, timeout=0.1) is True


def test_adaptive_rate_limiter_acquire_permit():
    limiter = AdaptiveRateLimiter(base_rate=50.0, max_rate=100.0, min_rate=1.0)
    assert limiter.acquire_permit(timeout=1.0) is True


def test_adaptive_rate_limiter_record_success():
    limiter = AdaptiveRateLimiter(base_rate=5.0, max_rate=20.0, min_rate=0.5)
    limiter.record_success()
    stats = limiter.get_stats()
    assert stats["recent_operations"] >= 0


def test_adaptive_rate_limiter_record_error():
    limiter = AdaptiveRateLimiter(base_rate=5.0, max_rate=20.0, min_rate=0.5)
    limiter.record_error("timeout")
    stats = limiter.get_stats()
    assert stats["recent_errors"] >= 1


def test_adaptive_rate_limiter_get_stats_structure():
    limiter = AdaptiveRateLimiter(base_rate=5.0, max_rate=20.0, min_rate=0.5)
    stats = limiter.get_stats()
    assert "current_rate" in stats
    assert "base_rate" in stats
    assert "tokens_available" in stats
    assert "bucket_capacity" in stats


def test_adaptive_rate_limiter_adjusts_down_on_high_error_rate():
    limiter = AdaptiveRateLimiter(base_rate=10.0, max_rate=20.0, min_rate=0.5)
    initial_rate = limiter.current_rate
    for _ in range(40):
        limiter.record_error("fail")
    for _ in range(5):
        limiter.record_success()
    assert limiter.current_rate <= initial_rate


def test_adaptive_rate_limiter_adjusts_up_on_low_error_rate():
    limiter = AdaptiveRateLimiter(base_rate=5.0, max_rate=20.0, min_rate=0.5)
    initial_rate = limiter.current_rate
    for _ in range(20):
        limiter.record_success()
    assert limiter.current_rate >= initial_rate


def test_batch_rate_limiter_adaptive_success_flow():
    limiter = BatchRateLimiter(
        max_concurrent=2,
        rate_per_second=50.0,
        burst_size=10,
        enable_adaptive=True,
    )
    assert limiter.acquire(timeout=1.0) is True
    limiter.release_success()
    stats = limiter.get_stats()
    assert stats["files_processed"] == 1
    assert stats["files_failed"] == 0


def test_batch_rate_limiter_non_adaptive_success_flow():
    limiter = BatchRateLimiter(
        max_concurrent=2,
        rate_per_second=50.0,
        burst_size=20,
        enable_adaptive=False,
    )
    assert limiter.acquire(timeout=1.0) is True
    limiter.release_success()
    stats = limiter.get_stats()
    assert stats["files_processed"] == 1


def test_batch_rate_limiter_error_flow():
    limiter = BatchRateLimiter(
        max_concurrent=2,
        rate_per_second=50.0,
        burst_size=10,
        enable_adaptive=True,
    )
    assert limiter.acquire(timeout=1.0) is True
    limiter.release_error("parse_error")
    stats = limiter.get_stats()
    assert stats["files_failed"] == 1


def test_batch_rate_limiter_non_adaptive_error_flow():
    limiter = BatchRateLimiter(
        max_concurrent=2,
        rate_per_second=50.0,
        burst_size=10,
        enable_adaptive=False,
    )
    assert limiter.acquire(timeout=1.0) is True
    limiter.release_error("io_error")
    stats = limiter.get_stats()
    assert stats["files_failed"] == 1


def test_batch_rate_limiter_semaphore_timeout():
    limiter = BatchRateLimiter(
        max_concurrent=1,
        rate_per_second=50.0,
        burst_size=10,
        enable_adaptive=False,
    )
    assert limiter.acquire(timeout=0.5) is True
    # Semaphore exhausted, second acquire should time out
    assert limiter.acquire(timeout=0.05) is False
    limiter.release_success()


def test_batch_rate_limiter_get_stats_with_multiple_operations():
    limiter = BatchRateLimiter(
        max_concurrent=5,
        rate_per_second=100.0,
        burst_size=50,
        enable_adaptive=True,
    )
    for _ in range(3):
        limiter.acquire(timeout=1.0)
        limiter.release_success()
    for _ in range(2):
        limiter.acquire(timeout=1.0)
        limiter.release_error("err")

    stats = limiter.get_stats()
    assert stats["files_processed"] == 3
    assert stats["files_failed"] == 2
    assert stats["success_rate"] == pytest.approx(0.6)
    assert stats["avg_wait_time"] >= 0.0


def test_batch_rate_limiter_stats_no_operations():
    limiter = BatchRateLimiter(max_concurrent=2, rate_per_second=50.0)
    stats = limiter.get_stats()
    assert stats["success_rate"] == 0.0
    assert stats["avg_wait_time"] == 0.0


def test_cleanup_memory_returns_metrics():
    result = cleanup_memory()
    assert result is None or ("rss_mb" in result and "vms_mb" in result)


def test_adaptive_rate_limiter_system_load_check():
    limiter = AdaptiveRateLimiter(base_rate=5.0, max_rate=20.0, min_rate=0.5)
    limiter.last_system_check = 0.0  # Force system check on next acquire
    # Should not raise
    limiter.acquire_permit(timeout=0.5)
