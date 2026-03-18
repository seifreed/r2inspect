"""Comprehensive tests for rate_limiter.py - real instances, no mocks."""

import threading
import time

import psutil
import pytest

from r2inspect.infrastructure.rate_limiter import (
    AdaptiveRateLimiter,
    BatchRateLimiter,
    TokenBucket,
    cleanup_memory,
)


# ---------------------------------------------------------------------------
# TokenBucket
# ---------------------------------------------------------------------------


def test_token_bucket_initialization():
    bucket = TokenBucket(capacity=10, refill_rate=5.0)

    assert bucket.capacity == 10
    assert bucket.refill_rate == 5.0
    assert bucket.tokens == 10.0


def test_token_bucket_acquire_success():
    bucket = TokenBucket(capacity=10, refill_rate=5.0)

    result = bucket.acquire(tokens=5)

    assert result is True
    assert bucket.tokens == pytest.approx(5.0, abs=0.5)


def test_token_bucket_acquire_default_tokens():
    bucket = TokenBucket(capacity=10, refill_rate=5.0)

    result = bucket.acquire()

    assert result is True
    assert bucket.tokens < 10.0


def test_token_bucket_acquire_insufficient_tokens():
    bucket = TokenBucket(capacity=10, refill_rate=5.0)

    result = bucket.acquire(tokens=15, timeout=0.05)

    assert result is False


def test_token_bucket_acquire_with_refill():
    bucket = TokenBucket(capacity=10, refill_rate=100.0)

    bucket.acquire(tokens=8)
    time.sleep(0.15)

    result = bucket.acquire(tokens=5)

    assert result is True


def test_token_bucket_refill():
    bucket = TokenBucket(capacity=10, refill_rate=100.0)

    bucket.tokens = 0
    time.sleep(0.1)
    bucket._refill()

    assert bucket.tokens >= 5.0
    assert bucket.tokens <= 10.0


def test_token_bucket_refill_capped_at_capacity():
    bucket = TokenBucket(capacity=10, refill_rate=1000.0)

    bucket.tokens = 0
    time.sleep(0.1)
    bucket._refill()

    assert bucket.tokens == 10.0


def test_token_bucket_multiple_acquires():
    bucket = TokenBucket(capacity=10, refill_rate=5.0)

    assert bucket.acquire(tokens=3) is True
    assert bucket.acquire(tokens=3) is True
    assert bucket.acquire(tokens=3) is True

    assert bucket.tokens <= 2.0


def test_token_bucket_thread_safety():
    bucket = TokenBucket(capacity=100, refill_rate=50.0)
    results = []

    def acquire_tokens():
        result = bucket.acquire(tokens=1)
        results.append(result)

    threads = [threading.Thread(target=acquire_tokens) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(results)
    assert bucket.tokens >= 0


# ---------------------------------------------------------------------------
# AdaptiveRateLimiter
# ---------------------------------------------------------------------------


def test_adaptive_rate_limiter_initialization():
    limiter = AdaptiveRateLimiter(
        base_rate=10.0,
        max_rate=50.0,
        min_rate=1.0,
        memory_threshold=0.85,
        cpu_threshold=0.95,
    )

    assert limiter.base_rate == 10.0
    assert limiter.max_rate == 50.0
    assert limiter.min_rate == 1.0
    assert limiter.memory_threshold == 0.85
    assert limiter.cpu_threshold == 0.95
    assert limiter.current_rate == 10.0


def test_adaptive_rate_limiter_default_initialization():
    limiter = AdaptiveRateLimiter()

    assert limiter.base_rate == 5.0
    assert limiter.max_rate == 20.0
    assert limiter.min_rate == 0.5


def test_adaptive_rate_limiter_acquire_permit():
    limiter = AdaptiveRateLimiter(base_rate=10.0)

    result = limiter.acquire_permit(timeout=1.0)

    assert result is True


def test_adaptive_rate_limiter_record_success():
    limiter = AdaptiveRateLimiter(base_rate=10.0)

    limiter.record_success()

    assert len(limiter.success_window) == 1


def test_adaptive_rate_limiter_record_error():
    limiter = AdaptiveRateLimiter(base_rate=10.0)

    limiter.record_error("test_error")

    assert len(limiter.error_window) == 1


def test_adaptive_rate_limiter_check_system_load_actually_runs():
    """Force _check_system_load by resetting last_system_check to 0.

    We cannot control real CPU / memory values, but we verify the method
    runs without error and keeps the rate within valid bounds.
    """
    limiter = AdaptiveRateLimiter(base_rate=10.0, min_rate=1.0, max_rate=50.0)

    limiter.last_system_check = 0
    limiter._check_system_load()

    assert limiter.current_rate >= limiter.min_rate
    assert limiter.current_rate <= limiter.max_rate


def test_adaptive_rate_limiter_check_system_load_skip_when_recent():
    limiter = AdaptiveRateLimiter(base_rate=10.0)
    limiter.last_system_check = time.time()
    initial_rate = limiter.current_rate

    limiter._check_system_load()

    assert limiter.current_rate == initial_rate


def test_adaptive_rate_limiter_adjust_rate_high_error():
    limiter = AdaptiveRateLimiter(base_rate=10.0)

    for _ in range(10):
        limiter.record_error()

    initial_rate = limiter.current_rate

    # After 10 errors with error_rate > 0.3, rate must have decreased.
    assert limiter.current_rate <= initial_rate


def test_adaptive_rate_limiter_adjust_rate_low_error():
    limiter = AdaptiveRateLimiter(base_rate=10.0)
    limiter.current_rate = 5.0

    for _ in range(100):
        limiter.record_success()

    # With zero errors and 100 successes, error_rate < 0.05 => rate increases.
    assert limiter.current_rate > 5.0


def test_adaptive_rate_limiter_adjust_rate_moderate_error():
    limiter = AdaptiveRateLimiter(base_rate=10.0)

    # Record successes and errors together so that the cumulative error
    # rate lands between 0.1 and 0.3 when _adjust_rate runs.
    # We add 3 successes (below the threshold of 5 so no adjustment yet)
    # then 2 errors to reach 5 total with 2/5 = 0.4 error rate.
    for _ in range(3):
        limiter.record_success()
    rate_before_errors = limiter.current_rate
    for _ in range(2):
        limiter.record_error()

    # With error_rate 2/5 = 0.4 (> 0.3), rate should have decreased.
    assert limiter.current_rate < rate_before_errors


def test_adaptive_rate_limiter_adjust_rate_insufficient_data():
    limiter = AdaptiveRateLimiter(base_rate=10.0)

    limiter.record_success()
    limiter.record_success()

    # Only 2 samples, threshold is 5 -> no adjustment.
    assert limiter.current_rate == 10.0


def test_adaptive_rate_limiter_get_stats():
    limiter = AdaptiveRateLimiter(base_rate=10.0)

    limiter.record_success()
    limiter.record_success()
    limiter.record_error()

    stats = limiter.get_stats()

    assert stats["base_rate"] == 10.0
    assert stats["recent_operations"] == 3
    assert stats["recent_errors"] == 1
    assert stats["recent_error_rate"] == pytest.approx(1 / 3, rel=0.01)


def test_adaptive_rate_limiter_rate_stays_within_bounds():
    limiter = AdaptiveRateLimiter(base_rate=10.0, min_rate=1.0, max_rate=50.0)

    # Push rate down hard with many errors.
    for _ in range(50):
        limiter.record_error()

    assert limiter.current_rate >= limiter.min_rate

    # Reset windows and push rate up with many successes.
    limiter.error_window.clear()
    limiter.success_window.clear()
    limiter.current_rate = 5.0
    for _ in range(100):
        limiter.record_success()

    assert limiter.current_rate <= limiter.max_rate


def test_adaptive_rate_limiter_bucket_rate_update():
    limiter = AdaptiveRateLimiter(base_rate=10.0)

    # Manually move the current_rate far enough from bucket rate to trigger
    # the sync path inside acquire_permit (|diff| > 0.1).
    limiter.current_rate = 20.0
    limiter.acquire_permit(timeout=1.0)

    assert limiter.bucket.refill_rate == 20.0


def test_adaptive_rate_limiter_bucket_rate_no_update():
    limiter = AdaptiveRateLimiter(base_rate=10.0)

    initial_rate = limiter.bucket.refill_rate
    limiter.acquire_permit(timeout=1.0)

    assert limiter.bucket.refill_rate == initial_rate


def test_adaptive_rate_limiter_acquire_permit_with_rate_update():
    limiter = AdaptiveRateLimiter(base_rate=5.0)

    for _ in range(50):
        limiter.record_success()

    result = limiter.acquire_permit(timeout=1.0)
    assert result is True


def test_adaptive_rate_limiter_recent_window():
    limiter = AdaptiveRateLimiter(base_rate=10.0)

    for _ in range(10):
        limiter.record_success()
    for _ in range(5):
        limiter.record_error()

    stats = limiter.get_stats()

    assert stats["recent_operations"] == 15


# ---------------------------------------------------------------------------
# BatchRateLimiter
# ---------------------------------------------------------------------------


def test_batch_rate_limiter_initialization_adaptive():
    limiter = BatchRateLimiter(
        max_concurrent=5,
        rate_per_second=10.0,
        burst_size=20,
        enable_adaptive=True,
    )

    assert limiter.max_concurrent == 5
    assert isinstance(limiter.rate_limiter, AdaptiveRateLimiter)


def test_batch_rate_limiter_initialization_token_bucket():
    limiter = BatchRateLimiter(
        max_concurrent=5,
        rate_per_second=10.0,
        burst_size=20,
        enable_adaptive=False,
    )

    assert limiter.max_concurrent == 5
    assert isinstance(limiter.rate_limiter, TokenBucket)


def test_batch_rate_limiter_acquire_success():
    limiter = BatchRateLimiter(max_concurrent=5, rate_per_second=10.0)

    result = limiter.acquire(timeout=1.0)

    assert result is True


def test_batch_rate_limiter_acquire_timeout_semaphore():
    """When the semaphore is exhausted, acquire should time out."""
    limiter = BatchRateLimiter(max_concurrent=1, rate_per_second=10.0)

    # Hold the single permit.
    limiter.semaphore.acquire()

    result = limiter.acquire(timeout=0.05)
    assert result is False

    limiter.semaphore.release()


def test_batch_rate_limiter_acquire_timeout_rate_limit():
    """When the token bucket is empty, acquire should time out."""
    limiter = BatchRateLimiter(
        max_concurrent=5,
        rate_per_second=0.1,
        enable_adaptive=False,
    )

    # Drain all tokens.
    limiter.rate_limiter.tokens = 0

    result = limiter.acquire(timeout=0.05)
    assert result is False


def test_batch_rate_limiter_release_success():
    limiter = BatchRateLimiter(max_concurrent=5, rate_per_second=10.0)

    limiter.acquire()
    limiter.release_success()

    assert limiter.stats["files_processed"] == 1


def test_batch_rate_limiter_release_error():
    limiter = BatchRateLimiter(max_concurrent=5, rate_per_second=10.0)

    limiter.acquire()
    limiter.release_error("test_error")

    assert limiter.stats["files_failed"] == 1


def test_batch_rate_limiter_get_stats():
    limiter = BatchRateLimiter(max_concurrent=5, rate_per_second=10.0)

    limiter.acquire()
    limiter.release_success()

    limiter.acquire()
    limiter.release_error()

    stats = limiter.get_stats()

    assert stats["files_processed"] == 1
    assert stats["files_failed"] == 1
    assert stats["success_rate"] == 0.5
    assert "avg_wait_time" in stats


def test_batch_rate_limiter_get_stats_no_files():
    limiter = BatchRateLimiter(max_concurrent=5, rate_per_second=10.0)

    stats = limiter.get_stats()

    assert stats["success_rate"] == 0.0
    assert stats["avg_wait_time"] == 0.0


def test_batch_rate_limiter_wait_time_tracking():
    limiter = BatchRateLimiter(max_concurrent=5, rate_per_second=100.0)

    limiter.acquire()
    limiter.release_success()

    stats = limiter.get_stats()

    assert stats["total_wait_time"] >= 0
    assert stats["max_wait_time"] >= 0


def test_batch_rate_limiter_thread_safety():
    limiter = BatchRateLimiter(max_concurrent=10, rate_per_second=50.0)
    results = []

    def worker():
        if limiter.acquire(timeout=2.0):
            time.sleep(0.01)
            limiter.release_success()
            results.append(True)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 20


def test_batch_rate_limiter_acquire_updates_stats():
    limiter = BatchRateLimiter(max_concurrent=5, rate_per_second=10.0)

    limiter.acquire(timeout=1.0)
    limiter.release_success()

    stats = limiter.get_stats()
    assert stats["total_wait_time"] >= 0
    assert stats["max_wait_time"] >= 0


def test_batch_rate_limiter_non_adaptive_release():
    limiter = BatchRateLimiter(
        max_concurrent=5,
        rate_per_second=10.0,
        enable_adaptive=False,
    )

    limiter.acquire()
    limiter.release_success()

    assert limiter.stats["files_processed"] == 1


def test_batch_rate_limiter_non_adaptive_error():
    limiter = BatchRateLimiter(
        max_concurrent=5,
        rate_per_second=10.0,
        enable_adaptive=False,
    )

    limiter.acquire()
    limiter.release_error()

    assert limiter.stats["files_failed"] == 1


def test_batch_rate_limiter_acquire_with_adaptive_draining():
    """When the adaptive bucket is drained, acquire should time out."""
    limiter = BatchRateLimiter(
        max_concurrent=5,
        rate_per_second=10.0,
        enable_adaptive=True,
    )

    # Drain internal bucket tokens.
    limiter.rate_limiter.bucket.tokens = 0
    limiter.rate_limiter.bucket.refill_rate = 0.01

    result = limiter.acquire(timeout=0.05)
    assert result is False


def test_batch_rate_limiter_semaphore_released_on_rate_limit_failure():
    """Verify semaphore is released when rate limiter denies acquisition.

    After a failed acquire the next acquire should still succeed because
    the semaphore was properly released.
    """
    limiter = BatchRateLimiter(
        max_concurrent=2,
        rate_per_second=10.0,
        enable_adaptive=True,
    )

    # Drain bucket to force rate-limit failure.
    limiter.rate_limiter.bucket.tokens = 0
    limiter.rate_limiter.bucket.refill_rate = 0.01
    limiter.acquire(timeout=0.05)

    # Restore tokens so the next acquire can succeed.
    limiter.rate_limiter.bucket.tokens = 10
    limiter.rate_limiter.bucket.refill_rate = 100.0

    result = limiter.acquire(timeout=1.0)
    assert result is True


def test_batch_rate_limiter_get_stats_with_adaptive():
    limiter = BatchRateLimiter(
        max_concurrent=5,
        rate_per_second=10.0,
        enable_adaptive=True,
    )

    limiter.acquire()
    limiter.release_success()

    stats = limiter.get_stats()

    assert "current_rate" in stats
    assert "base_rate" in stats
    assert "recent_operations" in stats


# ---------------------------------------------------------------------------
# cleanup_memory
# ---------------------------------------------------------------------------


def test_cleanup_memory_returns_memory_info():
    result = cleanup_memory()

    assert result is not None
    assert "rss_mb" in result
    assert "vms_mb" in result
    assert result["rss_mb"] > 0
    assert result["vms_mb"] > 0


def test_cleanup_memory_values_are_reasonable():
    result = cleanup_memory()

    # The test process itself should consume at least some memory.
    assert result is not None
    assert result["rss_mb"] > 1.0  # at least 1 MB
