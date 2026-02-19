#!/usr/bin/env python3
"""
Tests for r2inspect/utils/rate_limiter.py covering branches
not exercised by the existing test suite.
"""

import threading
import time

import pytest

from r2inspect.utils.rate_limiter import (
    AdaptiveRateLimiter,
    BatchRateLimiter,
    TokenBucket,
    cleanup_memory,
)


# ---------------------------------------------------------------------------
# TokenBucket
# ---------------------------------------------------------------------------

def test_token_bucket_init_attributes():
    bucket = TokenBucket(capacity=10, refill_rate=5.0)
    assert bucket.capacity == 10
    assert bucket.refill_rate == 5.0
    assert bucket.tokens == 10.0


def test_token_bucket_acquire_success():
    bucket = TokenBucket(capacity=5, refill_rate=100.0)
    assert bucket.acquire(tokens=1, timeout=0.1) is True
    assert bucket.tokens == pytest.approx(4.0, abs=0.1)


def test_token_bucket_acquire_timeout_returns_false():
    bucket = TokenBucket(capacity=1, refill_rate=0.001)
    assert bucket.acquire(tokens=1, timeout=0.05) is True
    # Bucket is now empty; tiny refill rate means we cannot get another token quickly
    assert bucket.acquire(tokens=1, timeout=0.02) is False


def test_token_bucket_acquire_no_timeout_eventually_succeeds():
    bucket = TokenBucket(capacity=1, refill_rate=200.0)
    assert bucket.acquire(tokens=1) is True
    # After draining, refill is fast enough that a second acquire eventually succeeds
    assert bucket.acquire(tokens=1, timeout=0.5) is True


def test_token_bucket_refill_adds_tokens_over_time():
    bucket = TokenBucket(capacity=10, refill_rate=100.0)
    bucket.tokens = 0.0
    time.sleep(0.05)
    bucket._refill()
    assert bucket.tokens > 0.0


def test_token_bucket_refill_does_not_exceed_capacity():
    bucket = TokenBucket(capacity=5, refill_rate=1000.0)
    bucket.tokens = 0.0
    time.sleep(0.1)
    bucket._refill()
    assert bucket.tokens <= float(bucket.capacity)


# ---------------------------------------------------------------------------
# AdaptiveRateLimiter – init
# ---------------------------------------------------------------------------

def test_adaptive_rate_limiter_init_defaults():
    rl = AdaptiveRateLimiter()
    assert rl.base_rate == 5.0
    assert rl.max_rate == 20.0
    assert rl.min_rate == 0.5
    assert rl.memory_threshold == 0.8
    assert rl.cpu_threshold == 0.9
    assert rl.current_rate == rl.base_rate


def test_adaptive_rate_limiter_init_custom():
    rl = AdaptiveRateLimiter(base_rate=10.0, max_rate=50.0, min_rate=1.0,
                             memory_threshold=0.7, cpu_threshold=0.8)
    assert rl.base_rate == 10.0
    assert rl.max_rate == 50.0
    assert rl.min_rate == 1.0


# ---------------------------------------------------------------------------
# AdaptiveRateLimiter – acquire_permit
# ---------------------------------------------------------------------------

def test_acquire_permit_returns_true_with_capacity():
    rl = AdaptiveRateLimiter(base_rate=100.0, max_rate=200.0, min_rate=1.0)
    assert rl.acquire_permit(timeout=1.0) is True


def test_acquire_permit_updates_bucket_rate_when_diverged():
    rl = AdaptiveRateLimiter(base_rate=10.0, max_rate=50.0, min_rate=1.0)
    # Force a rate divergence so the if-branch inside acquire_permit fires
    rl.current_rate = 25.0
    rl.bucket.refill_rate = 10.0
    rl.acquire_permit(timeout=1.0)
    assert abs(rl.bucket.refill_rate - 25.0) < 0.5


# ---------------------------------------------------------------------------
# AdaptiveRateLimiter – record_success / record_error
# ---------------------------------------------------------------------------

def test_record_success_appends_to_success_window():
    rl = AdaptiveRateLimiter(base_rate=5.0)
    initial = len(rl.success_window)
    rl.record_success()
    assert len(rl.success_window) == initial + 1


def test_record_error_appends_to_error_window():
    rl = AdaptiveRateLimiter(base_rate=5.0)
    initial = len(rl.error_window)
    rl.record_error("timeout")
    assert len(rl.error_window) == initial + 1


# ---------------------------------------------------------------------------
# AdaptiveRateLimiter – _check_system_load
# ---------------------------------------------------------------------------

def test_check_system_load_skips_when_within_interval():
    rl = AdaptiveRateLimiter(base_rate=5.0)
    rl.last_system_check = time.time()  # just checked
    rate_before = rl.current_rate
    rl._check_system_load()
    assert rl.current_rate == rate_before  # unchanged


def test_check_system_load_runs_when_interval_elapsed():
    rl = AdaptiveRateLimiter(base_rate=5.0, max_rate=20.0, min_rate=0.5)
    rl.last_system_check = 0.0  # force check
    rl._check_system_load()
    # Should have updated last_system_check
    assert rl.last_system_check > 1.0


# ---------------------------------------------------------------------------
# AdaptiveRateLimiter – _adjust_rate
# ---------------------------------------------------------------------------

def test_adjust_rate_not_enough_data_does_nothing():
    rl = AdaptiveRateLimiter(base_rate=5.0)
    rate_before = rl.current_rate
    # Only 4 total operations – below the minimum of 5
    now = time.time()
    rl.error_window.append(now)
    rl.success_window.extend([now, now, now])
    rl._adjust_rate()
    assert rl.current_rate == rate_before


def test_adjust_rate_high_error_rate_reduces_rate():
    rl = AdaptiveRateLimiter(base_rate=10.0, max_rate=20.0, min_rate=0.5)
    now = time.time()
    # 4 errors out of 5 total = 80% error rate (> 0.3 threshold)
    for _ in range(4):
        rl.error_window.append(now)
    rl.success_window.append(now)
    rate_before = rl.current_rate
    rl._adjust_rate()
    assert rl.current_rate < rate_before


def test_adjust_rate_moderate_error_rate_reduces_rate_moderately():
    rl = AdaptiveRateLimiter(base_rate=10.0, max_rate=20.0, min_rate=0.5)
    now = time.time()
    # 2 errors out of 10 total = 20% error rate (between 0.1 and 0.3)
    for _ in range(2):
        rl.error_window.append(now)
    for _ in range(8):
        rl.success_window.append(now)
    rate_before = rl.current_rate
    rl._adjust_rate()
    assert rl.current_rate < rate_before
    assert rl.current_rate >= rl.min_rate


def test_adjust_rate_low_error_rate_increases_rate():
    rl = AdaptiveRateLimiter(base_rate=5.0, max_rate=20.0, min_rate=0.5)
    now = time.time()
    # 0 errors out of 20 total = 0% error rate (< 0.05 threshold)
    for _ in range(20):
        rl.success_window.append(now)
    rate_before = rl.current_rate
    rl._adjust_rate()
    assert rl.current_rate > rate_before
    assert rl.current_rate <= rl.max_rate


def test_adjust_rate_respects_min_rate_floor():
    rl = AdaptiveRateLimiter(base_rate=0.5, max_rate=20.0, min_rate=0.5)
    rl.current_rate = 0.5  # already at minimum
    now = time.time()
    for _ in range(4):
        rl.error_window.append(now)
    rl.success_window.append(now)
    rl._adjust_rate()
    assert rl.current_rate >= rl.min_rate


# ---------------------------------------------------------------------------
# AdaptiveRateLimiter – get_stats
# ---------------------------------------------------------------------------

def test_get_stats_structure():
    rl = AdaptiveRateLimiter(base_rate=5.0)
    stats = rl.get_stats()
    assert "current_rate" in stats
    assert "base_rate" in stats
    assert "recent_operations" in stats
    assert "recent_errors" in stats
    assert "recent_error_rate" in stats
    assert "tokens_available" in stats
    assert "bucket_capacity" in stats


def test_get_stats_reflects_recorded_errors():
    rl = AdaptiveRateLimiter(base_rate=5.0)
    rl.record_error("parse_error")
    stats = rl.get_stats()
    assert stats["recent_errors"] >= 1


def test_get_stats_recent_error_rate_calculation():
    rl = AdaptiveRateLimiter(base_rate=5.0)
    for _ in range(3):
        rl.record_error("err")
    for _ in range(7):
        rl.record_success()
    stats = rl.get_stats()
    assert stats["recent_operations"] == 10
    assert abs(stats["recent_error_rate"] - 0.3) < 0.05


# ---------------------------------------------------------------------------
# BatchRateLimiter – adaptive mode
# ---------------------------------------------------------------------------

def test_batch_rate_limiter_adaptive_init():
    limiter = BatchRateLimiter(
        max_concurrent=5, rate_per_second=10.0, burst_size=20, enable_adaptive=True
    )
    assert isinstance(limiter.rate_limiter, AdaptiveRateLimiter)
    assert limiter.adaptive is True


def test_batch_rate_limiter_non_adaptive_init():
    limiter = BatchRateLimiter(
        max_concurrent=5, rate_per_second=10.0, burst_size=20, enable_adaptive=False
    )
    assert isinstance(limiter.rate_limiter, TokenBucket)
    assert limiter.adaptive is False


def test_batch_rate_limiter_adaptive_acquire_and_release_success():
    limiter = BatchRateLimiter(
        max_concurrent=2, rate_per_second=50.0, burst_size=10, enable_adaptive=True
    )
    assert limiter.acquire(timeout=1.0) is True
    limiter.release_success()
    stats = limiter.get_stats()
    assert stats["files_processed"] == 1
    assert stats["files_failed"] == 0


def test_batch_rate_limiter_adaptive_acquire_and_release_error():
    limiter = BatchRateLimiter(
        max_concurrent=2, rate_per_second=50.0, burst_size=10, enable_adaptive=True
    )
    assert limiter.acquire(timeout=1.0) is True
    limiter.release_error("io_error")
    stats = limiter.get_stats()
    assert stats["files_failed"] == 1
    assert stats["files_processed"] == 0


def test_batch_rate_limiter_non_adaptive_release_error_does_not_record():
    """release_error with non-adaptive limiter only increments stats counter."""
    limiter = BatchRateLimiter(
        max_concurrent=2, rate_per_second=50.0, burst_size=20, enable_adaptive=False
    )
    assert limiter.acquire(timeout=1.0) is True
    limiter.release_error("timeout")
    stats = limiter.get_stats()
    assert stats["files_failed"] == 1


def test_batch_rate_limiter_non_adaptive_release_success():
    limiter = BatchRateLimiter(
        max_concurrent=2, rate_per_second=50.0, burst_size=20, enable_adaptive=False
    )
    assert limiter.acquire(timeout=1.0) is True
    limiter.release_success()
    stats = limiter.get_stats()
    assert stats["files_processed"] == 1


# ---------------------------------------------------------------------------
# BatchRateLimiter – acquire failure paths
# ---------------------------------------------------------------------------

def test_batch_rate_limiter_semaphore_timeout_returns_false():
    limiter = BatchRateLimiter(
        max_concurrent=1, rate_per_second=50.0, burst_size=10, enable_adaptive=False
    )
    assert limiter.acquire(timeout=0.5) is True
    # Semaphore exhausted – next acquire must time out
    assert limiter.acquire(timeout=0.05) is False
    limiter.release_success()


def test_batch_rate_limiter_rate_limit_failure_releases_semaphore():
    """When the token bucket is drained and timeout is short, acquire returns False
    but the semaphore is properly released so subsequent acquires succeed."""
    limiter = BatchRateLimiter(
        max_concurrent=5, rate_per_second=0.001, burst_size=1, enable_adaptive=False
    )
    # Drain the bucket
    limiter.rate_limiter.tokens = 0.0
    result = limiter.acquire(timeout=0.02)
    assert result is False
    # Semaphore must have been released; restore tokens and verify re-acquire works
    limiter.rate_limiter.tokens = 5.0
    assert limiter.acquire(timeout=0.5) is True
    limiter.release_success()


# ---------------------------------------------------------------------------
# BatchRateLimiter – get_stats
# ---------------------------------------------------------------------------

def test_batch_rate_limiter_get_stats_no_operations():
    limiter = BatchRateLimiter(max_concurrent=2, rate_per_second=50.0)
    stats = limiter.get_stats()
    assert stats["success_rate"] == 0.0
    assert stats["avg_wait_time"] == 0.0


def test_batch_rate_limiter_get_stats_success_rate():
    limiter = BatchRateLimiter(
        max_concurrent=5, rate_per_second=100.0, burst_size=50, enable_adaptive=True
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


def test_batch_rate_limiter_get_stats_includes_rate_limiter_stats_when_adaptive():
    limiter = BatchRateLimiter(
        max_concurrent=2, rate_per_second=50.0, enable_adaptive=True
    )
    stats = limiter.get_stats()
    # AdaptiveRateLimiter stats keys should be present
    assert "current_rate" in stats
    assert "tokens_available" in stats


def test_batch_rate_limiter_get_stats_no_rate_limiter_stats_when_non_adaptive():
    limiter = BatchRateLimiter(
        max_concurrent=2, rate_per_second=50.0, enable_adaptive=False
    )
    stats = limiter.get_stats()
    assert "current_rate" not in stats


# ---------------------------------------------------------------------------
# cleanup_memory
# ---------------------------------------------------------------------------

def test_cleanup_memory_returns_dict_or_none():
    result = cleanup_memory()
    assert result is None or (
        isinstance(result, dict) and "rss_mb" in result and "vms_mb" in result
    )


def test_cleanup_memory_values_are_positive_when_returned():
    result = cleanup_memory()
    if result is not None:
        assert result["rss_mb"] > 0
        assert result["vms_mb"] > 0
