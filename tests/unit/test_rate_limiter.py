import time

from r2inspect.utils.rate_limiter import BatchRateLimiter, TokenBucket, cleanup_memory


def test_token_bucket_acquire_and_refill():
    bucket = TokenBucket(capacity=1, refill_rate=50.0)
    assert bucket.acquire(tokens=1, timeout=0.01) is True
    assert bucket.acquire(tokens=1, timeout=0.01) is False
    time.sleep(0.03)
    assert bucket.acquire(tokens=1, timeout=0.05) is True


def test_batch_rate_limiter_success_stats():
    limiter = BatchRateLimiter(
        max_concurrent=1,
        rate_per_second=100.0,
        burst_size=1,
        enable_adaptive=False,
    )
    assert limiter.acquire(timeout=0.1) is True
    limiter.release_success()

    stats = limiter.get_stats()
    assert stats["files_processed"] == 1
    assert stats["files_failed"] == 0
    assert stats["success_rate"] == 1.0


def test_cleanup_memory_returns_metrics_or_none():
    result = cleanup_memory()
    assert result is None or ("rss_mb" in result and "vms_mb" in result)
