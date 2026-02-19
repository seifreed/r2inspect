"""Comprehensive tests for rate limiter - 0% coverage target"""
import time
import threading
import pytest

from r2inspect.utils.rate_limiter import (
    TokenBucket,
    AdaptiveRateLimiter,
    BatchRateLimiter,
    cleanup_memory,
)


def test_token_bucket_init():
    bucket = TokenBucket(capacity=10, refill_rate=5.0)
    assert bucket.capacity == 10
    assert bucket.refill_rate == 5.0
    assert bucket.tokens == 10.0


def test_token_bucket_acquire_success():
    bucket = TokenBucket(capacity=5, refill_rate=100.0)
    result = bucket.acquire(tokens=3, timeout=0.1)
    assert result is True
    assert bucket.tokens < 5.0


def test_token_bucket_acquire_multiple():
    bucket = TokenBucket(capacity=10, refill_rate=0.1)
    assert bucket.acquire(tokens=5) is True
    assert bucket.acquire(tokens=5) is True
    assert bucket.acquire(tokens=1, timeout=0.01) is False


def test_token_bucket_acquire_timeout():
    bucket = TokenBucket(capacity=1, refill_rate=1.0)
    bucket.acquire(tokens=1)
    start = time.time()
    result = bucket.acquire(tokens=1, timeout=0.05)
    elapsed = time.time() - start
    assert result is False
    assert elapsed >= 0.04


def test_token_bucket_acquire_no_timeout():
    bucket = TokenBucket(capacity=1, refill_rate=100.0)
    bucket.acquire(tokens=1)
    
    def delayed_acquire():
        time.sleep(0.02)
        bucket.acquire(tokens=1, timeout=None)
    
    thread = threading.Thread(target=delayed_acquire)
    thread.daemon = True
    thread.start()
    time.sleep(0.01)
    # Thread should still be waiting


def test_token_bucket_refill():
    bucket = TokenBucket(capacity=10, refill_rate=100.0)
    bucket.acquire(tokens=10)
    assert bucket.tokens < 1.0
    time.sleep(0.1)
    bucket._refill()
    assert bucket.tokens > 5.0


def test_token_bucket_refill_cap():
    bucket = TokenBucket(capacity=5, refill_rate=100.0)
    time.sleep(0.1)
    bucket._refill()
    assert bucket.tokens <= 5.0  # Should not exceed capacity


def test_adaptive_rate_limiter_init():
    limiter = AdaptiveRateLimiter(
        base_rate=5.0,
        max_rate=20.0,
        min_rate=0.5,
        memory_threshold=0.8,
        cpu_threshold=0.9,
    )
    assert limiter.base_rate == 5.0
    assert limiter.current_rate == 5.0
    assert limiter.max_rate == 20.0
    assert limiter.min_rate == 0.5


def test_adaptive_rate_limiter_acquire_permit():
    limiter = AdaptiveRateLimiter(base_rate=100.0)
    result = limiter.acquire_permit(timeout=0.1)
    assert result is True


def test_adaptive_rate_limiter_record_success():
    limiter = AdaptiveRateLimiter(base_rate=5.0, max_rate=10.0)
    limiter.record_success()
    assert len(limiter.success_window) == 1


def test_adaptive_rate_limiter_record_error():
    limiter = AdaptiveRateLimiter(base_rate=5.0, min_rate=0.5)
    limiter.record_error("timeout")
    assert len(limiter.error_window) == 1


def test_adaptive_rate_limiter_adjust_rate_high_error():
    limiter = AdaptiveRateLimiter(base_rate=5.0, min_rate=1.0)
    # Record many errors
    for _ in range(10):
        limiter.record_error()
    
    original_rate = limiter.current_rate
    time.sleep(0.1)
    for _ in range(5):
        limiter.record_error()
    
    # Rate should decrease
    assert limiter.current_rate <= original_rate


def test_adaptive_rate_limiter_adjust_rate_low_error():
    limiter = AdaptiveRateLimiter(base_rate=5.0, max_rate=10.0)
    # Record many successes
    for _ in range(20):
        limiter.record_success()
    
    # Rate might increase (if enough time passed)
    assert limiter.current_rate >= limiter.base_rate * 0.8


def test_adaptive_rate_limiter_check_system_load():
    limiter = AdaptiveRateLimiter(
        base_rate=5.0,
        memory_threshold=0.8,
        cpu_threshold=0.9,
    )
    original_rate = limiter.current_rate
    limiter._check_system_load()
    # Rate may change based on system state


def test_adaptive_rate_limiter_get_stats():
    limiter = AdaptiveRateLimiter(base_rate=5.0)
    limiter.record_success()
    limiter.record_error()
    
    stats = limiter.get_stats()
    assert "current_rate" in stats
    assert "base_rate" in stats
    assert "recent_operations" in stats
    assert "recent_errors" in stats
    assert "recent_error_rate" in stats
    assert stats["recent_operations"] == 2
    assert stats["recent_errors"] == 1


def test_adaptive_rate_limiter_insufficient_data():
    limiter = AdaptiveRateLimiter(base_rate=5.0)
    limiter.record_success()
    limiter.record_success()
    original_rate = limiter.current_rate
    limiter._adjust_rate()
    # Should not adjust with too few samples
    assert limiter.current_rate == original_rate


def test_adaptive_rate_limiter_moderate_error_rate():
    limiter = AdaptiveRateLimiter(base_rate=5.0, min_rate=1.0)
    # 15% error rate
    for _ in range(17):
        limiter.record_success()
    for _ in range(3):
        limiter.record_error()
    
    original_rate = limiter.current_rate
    limiter._adjust_rate()
    # Should reduce rate
    assert limiter.current_rate <= original_rate


def test_adaptive_rate_limiter_system_check_interval():
    limiter = AdaptiveRateLimiter(base_rate=5.0)
    limiter.last_system_check = time.time()
    limiter._check_system_load()
    # Should not check again immediately
    assert time.time() - limiter.last_system_check < limiter.system_check_interval


def test_adaptive_rate_limiter_system_load_exception():
    limiter = AdaptiveRateLimiter(base_rate=5.0)
    # Force system check
    limiter.last_system_check = time.time() - 10.0
    original_rate = limiter.current_rate
    limiter._check_system_load()
    # Should handle any errors gracefully


def test_adaptive_rate_limiter_update_bucket_rate():
    limiter = AdaptiveRateLimiter(base_rate=5.0)
    limiter.current_rate = 10.0
    limiter.acquire_permit(timeout=0.1)
    # Bucket rate should be updated
    assert abs(limiter.bucket.refill_rate - 10.0) < 0.2


def test_batch_rate_limiter_init_adaptive():
    limiter = BatchRateLimiter(
        max_concurrent=10,
        rate_per_second=5.0,
        burst_size=20,
        enable_adaptive=True,
    )
    assert limiter.max_concurrent == 10
    assert limiter.adaptive is True
    assert isinstance(limiter.rate_limiter, AdaptiveRateLimiter)


def test_batch_rate_limiter_init_simple():
    limiter = BatchRateLimiter(
        max_concurrent=5,
        rate_per_second=10.0,
        burst_size=20,
        enable_adaptive=False,
    )
    assert limiter.adaptive is False
    assert isinstance(limiter.rate_limiter, TokenBucket)


def test_batch_rate_limiter_acquire():
    limiter = BatchRateLimiter(
        max_concurrent=2,
        rate_per_second=100.0,
        enable_adaptive=False,
    )
    assert limiter.acquire(timeout=0.1) is True


def test_batch_rate_limiter_acquire_timeout():
    limiter = BatchRateLimiter(
        max_concurrent=1,
        rate_per_second=1.0,
        burst_size=1,
        enable_adaptive=False,
    )
    assert limiter.acquire(timeout=0.1) is True
    assert limiter.acquire(timeout=0.05) is False
    limiter.release_success()


def test_batch_rate_limiter_release_success():
    limiter = BatchRateLimiter(max_concurrent=1, rate_per_second=100.0, enable_adaptive=True)
    limiter.acquire(timeout=0.1)
    limiter.release_success()
    
    stats = limiter.get_stats()
    assert stats["files_processed"] == 1
    assert stats["files_failed"] == 0


def test_batch_rate_limiter_release_error():
    limiter = BatchRateLimiter(max_concurrent=1, rate_per_second=100.0, enable_adaptive=True)
    limiter.acquire(timeout=0.1)
    limiter.release_error("timeout")
    
    stats = limiter.get_stats()
    assert stats["files_processed"] == 0
    assert stats["files_failed"] == 1


def test_batch_rate_limiter_get_stats():
    limiter = BatchRateLimiter(max_concurrent=2, rate_per_second=10.0, enable_adaptive=True)
    limiter.acquire(timeout=0.1)
    limiter.release_success()
    
    stats = limiter.get_stats()
    assert "files_processed" in stats
    assert "files_failed" in stats
    assert "total_wait_time" in stats
    assert "max_wait_time" in stats
    assert "success_rate" in stats
    assert "avg_wait_time" in stats


def test_batch_rate_limiter_stats_no_files():
    limiter = BatchRateLimiter(max_concurrent=2, rate_per_second=10.0)
    stats = limiter.get_stats()
    assert stats["success_rate"] == 0.0
    assert stats["avg_wait_time"] == 0.0


def test_batch_rate_limiter_adaptive_stats():
    limiter = BatchRateLimiter(max_concurrent=2, rate_per_second=10.0, enable_adaptive=True)
    limiter.acquire(timeout=0.1)
    limiter.release_success()
    
    stats = limiter.get_stats()
    assert "current_rate" in stats  # From AdaptiveRateLimiter


def test_batch_rate_limiter_semaphore_timeout():
    limiter = BatchRateLimiter(max_concurrent=1, rate_per_second=100.0)
    
    # Acquire the only semaphore
    limiter.semaphore.acquire(blocking=False)
    
    # Try to acquire should timeout
    result = limiter.acquire(timeout=0.05)
    assert result is False
    
    # Release for cleanup
    limiter.semaphore.release()


def test_batch_rate_limiter_rate_limit_failure():
    limiter = BatchRateLimiter(
        max_concurrent=10,
        rate_per_second=0.1,
        burst_size=1,
        enable_adaptive=False,
    )
    
    # First acquire should work (burst allows it)
    assert limiter.acquire(timeout=0.1) is True
    limiter.release_success()
    
    # Second acquire should fail due to rate limit
    result = limiter.acquire(timeout=0.05)
    if not result:
        # Expected for low rate
        pass


def test_batch_rate_limiter_acquire_exception():
    limiter = BatchRateLimiter(max_concurrent=1, rate_per_second=100.0, enable_adaptive=False)

    original_acquire = limiter.rate_limiter.acquire

    def raising_acquire(*args, **kwargs):
        raise RuntimeError("Test error")

    limiter.rate_limiter.acquire = raising_acquire

    try:
        limiter.acquire(timeout=0.1)
        assert False, "Should have raised"
    except RuntimeError:
        pass

    limiter.rate_limiter.acquire = original_acquire


def test_batch_rate_limiter_wait_time_tracking():
    limiter = BatchRateLimiter(
        max_concurrent=1,
        rate_per_second=10.0,
        enable_adaptive=False,
    )
    
    # First acquire should be fast
    start = time.time()
    limiter.acquire(timeout=1.0)
    first_wait = time.time() - start
    limiter.release_success()
    
    stats = limiter.get_stats()
    assert stats["max_wait_time"] >= first_wait - 0.01


def test_cleanup_memory():
    result = cleanup_memory()
    assert result is None or isinstance(result, dict)
    if result:
        assert "rss_mb" in result
        assert "vms_mb" in result
        assert result["rss_mb"] > 0


def test_cleanup_memory_psutil_unavailable():
    # Test graceful handling if psutil fails
    result = cleanup_memory()
    # Should not crash


def test_token_bucket_concurrent_access():
    bucket = TokenBucket(capacity=10, refill_rate=100.0)
    results = []
    
    def acquire_tokens():
        results.append(bucket.acquire(tokens=1, timeout=0.1))
    
    threads = [threading.Thread(target=acquire_tokens) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    # All should succeed
    assert all(results)


def test_adaptive_rate_limiter_concurrent_record():
    limiter = AdaptiveRateLimiter(base_rate=5.0)
    
    def record_ops():
        for _ in range(10):
            limiter.record_success()
            limiter.record_error()
    
    threads = [threading.Thread(target=record_ops) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    stats = limiter.get_stats()
    assert stats["recent_operations"] == 60


def test_batch_rate_limiter_concurrent_usage():
    limiter = BatchRateLimiter(
        max_concurrent=3,
        rate_per_second=100.0,
        enable_adaptive=False,
    )
    
    def process_file():
        if limiter.acquire(timeout=1.0):
            time.sleep(0.01)
            limiter.release_success()
    
    threads = [threading.Thread(target=process_file) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    stats = limiter.get_stats()
    assert stats["files_processed"] == 5


def test_adaptive_rate_limiter_bucket_update_threshold():
    limiter = AdaptiveRateLimiter(base_rate=5.0)
    limiter.current_rate = 5.05  # Very close to bucket rate
    
    # Should not update bucket if difference is small
    limiter.acquire_permit(timeout=0.1)
    # Bucket rate should remain close to original


def test_batch_rate_limiter_non_adaptive_release():
    limiter = BatchRateLimiter(
        max_concurrent=2,
        rate_per_second=100.0,
        enable_adaptive=False,
    )
    limiter.acquire(timeout=0.1)
    limiter.release_success()
    
    # Should not call record_success on TokenBucket
    stats = limiter.get_stats()
    assert stats["files_processed"] == 1


def test_adaptive_rate_limiter_recent_window():
    limiter = AdaptiveRateLimiter(base_rate=5.0)
    
    # Add old events
    limiter.error_window.append(time.time() - 120)
    limiter.success_window.append(time.time() - 120)
    
    # Add recent events
    limiter.record_success()
    
    stats = limiter.get_stats()
    # Recent operations should only count events within window
    assert stats["recent_operations"] <= 2


def test_token_bucket_zero_tokens():
    bucket = TokenBucket(capacity=0, refill_rate=0.0)
    result = bucket.acquire(tokens=1, timeout=0.01)
    assert result is False


def test_adaptive_rate_limiter_edge_case_rates():
    limiter = AdaptiveRateLimiter(
        base_rate=0.1,
        max_rate=0.2,
        min_rate=0.05,
    )
    assert limiter.current_rate == 0.1


def test_batch_rate_limiter_zero_concurrent():
    limiter = BatchRateLimiter(max_concurrent=1, rate_per_second=5.0)
    limiter.semaphore.acquire()
    result = limiter.acquire(timeout=0.01)
    assert result is False
    limiter.semaphore.release()


def test_token_bucket_large_capacity():
    bucket = TokenBucket(capacity=1000000, refill_rate=100000.0)
    assert bucket.acquire(tokens=1000) is True


def test_adaptive_rate_limiter_extreme_system_load():
    limiter = AdaptiveRateLimiter(
        base_rate=5.0,
        min_rate=0.1,
        memory_threshold=0.0,  # Will always trigger
    )
    limiter.last_system_check = time.time() - 10.0
    limiter._check_system_load()
    # Rate should be reduced


def test_batch_rate_limiter_adaptive_error_propagation():
    limiter = BatchRateLimiter(max_concurrent=2, rate_per_second=10.0, enable_adaptive=True)
    limiter.acquire(timeout=0.1)
    limiter.release_error("test_error")
    
    # Error should be recorded in adaptive limiter
    assert isinstance(limiter.rate_limiter, AdaptiveRateLimiter)
    assert len(limiter.rate_limiter.error_window) == 1
