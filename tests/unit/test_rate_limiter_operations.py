"""Comprehensive tests for rate_limiter.py - achieving 100% coverage."""

import pytest
import time
import threading
from unittest.mock import MagicMock, patch
from r2inspect.utils.rate_limiter import (
    TokenBucket,
    AdaptiveRateLimiter,
    BatchRateLimiter,
    cleanup_memory,
)


def test_token_bucket_initialization():
    bucket = TokenBucket(capacity=10, refill_rate=5.0)

    assert bucket.capacity == 10
    assert bucket.refill_rate == 5.0
    assert bucket.tokens == 10.0


def test_token_bucket_acquire_success():
    bucket = TokenBucket(capacity=10, refill_rate=5.0)

    result = bucket.acquire(tokens=5)

    assert result is True
    assert bucket.tokens == 5.0


def test_token_bucket_acquire_insufficient_tokens():
    bucket = TokenBucket(capacity=10, refill_rate=5.0)

    result = bucket.acquire(tokens=15, timeout=0.01)

    assert result is False


def test_token_bucket_acquire_with_refill():
    bucket = TokenBucket(capacity=10, refill_rate=10.0)

    bucket.acquire(tokens=8)
    time.sleep(0.5)

    result = bucket.acquire(tokens=5)

    assert result is True


def test_token_bucket_refill():
    bucket = TokenBucket(capacity=10, refill_rate=10.0)

    bucket.tokens = 0
    time.sleep(0.5)
    bucket._refill()

    assert bucket.tokens >= 4.0
    assert bucket.tokens <= 10.0


def test_token_bucket_refill_capped():
    bucket = TokenBucket(capacity=10, refill_rate=100.0)

    bucket.tokens = 0
    time.sleep(1.0)
    bucket._refill()

    assert bucket.tokens == 10.0


def test_token_bucket_thread_safety():
    bucket = TokenBucket(capacity=100, refill_rate=50.0)
    results = []

    def acquire_tokens():
        result = bucket.acquire(tokens=1)
        results.append(result)

    threads = []
    for _ in range(50):
        thread = threading.Thread(target=acquire_tokens)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    assert all(results)
    assert bucket.tokens >= 0


def test_adaptive_rate_limiter_initialization():
    limiter = AdaptiveRateLimiter(
        base_rate=10.0,
        max_rate=50.0,
        min_rate=1.0,
        memory_threshold=0.85,
        cpu_threshold=0.95
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


@patch('psutil.virtual_memory')
@patch('psutil.cpu_percent')
def test_adaptive_rate_limiter_check_system_load_high(mock_cpu, mock_memory):
    mock_memory.return_value.percent = 85.0
    mock_cpu.return_value = 95.0

    limiter = AdaptiveRateLimiter(base_rate=10.0)
    initial_rate = limiter.current_rate

    limiter.last_system_check = 0
    limiter._check_system_load()

    assert limiter.current_rate < initial_rate


@patch('psutil.virtual_memory')
@patch('psutil.cpu_percent')
def test_adaptive_rate_limiter_check_system_load_low(mock_cpu, mock_memory):
    mock_memory.return_value.percent = 50.0
    mock_cpu.return_value = 60.0

    limiter = AdaptiveRateLimiter(base_rate=10.0)
    limiter.current_rate = 5.0

    limiter.last_system_check = 0
    limiter._check_system_load()

    assert limiter.current_rate > 5.0


@patch('psutil.virtual_memory')
@patch('psutil.cpu_percent')
def test_adaptive_rate_limiter_check_system_load_exception(mock_cpu, mock_memory):
    mock_memory.side_effect = Exception("Error")

    limiter = AdaptiveRateLimiter(base_rate=10.0)
    initial_rate = limiter.current_rate

    limiter.last_system_check = 0
    limiter._check_system_load()

    assert limiter.current_rate <= initial_rate


def test_adaptive_rate_limiter_check_system_load_skip():
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
    limiter._adjust_rate()

    assert limiter.current_rate <= initial_rate


def test_adaptive_rate_limiter_adjust_rate_low_error():
    limiter = AdaptiveRateLimiter(base_rate=10.0)
    limiter.current_rate = 5.0

    for _ in range(100):
        limiter.record_success()

    limiter._adjust_rate()

    assert limiter.current_rate > 5.0


def test_adaptive_rate_limiter_adjust_rate_moderate_error():
    limiter = AdaptiveRateLimiter(base_rate=10.0)

    for _ in range(8):
        limiter.record_success()
    for _ in range(2):
        limiter.record_error()

    initial_rate = limiter.current_rate
    limiter._adjust_rate()

    assert limiter.current_rate < initial_rate


def test_adaptive_rate_limiter_adjust_rate_insufficient_data():
    limiter = AdaptiveRateLimiter(base_rate=10.0)

    limiter.record_success()
    limiter.record_success()

    initial_rate = limiter.current_rate
    limiter._adjust_rate()

    assert limiter.current_rate == initial_rate


def test_adaptive_rate_limiter_get_stats():
    limiter = AdaptiveRateLimiter(base_rate=10.0)

    limiter.record_success()
    limiter.record_success()
    limiter.record_error()

    stats = limiter.get_stats()

    assert stats["current_rate"] == 10.0
    assert stats["base_rate"] == 10.0
    assert stats["recent_operations"] == 3
    assert stats["recent_errors"] == 1
    assert stats["recent_error_rate"] == pytest.approx(0.333, rel=0.01)


def test_batch_rate_limiter_initialization_adaptive():
    limiter = BatchRateLimiter(
        max_concurrent=5,
        rate_per_second=10.0,
        burst_size=20,
        enable_adaptive=True
    )

    assert limiter.max_concurrent == 5
    assert isinstance(limiter.rate_limiter, AdaptiveRateLimiter)


def test_batch_rate_limiter_initialization_token_bucket():
    limiter = BatchRateLimiter(
        max_concurrent=5,
        rate_per_second=10.0,
        burst_size=20,
        enable_adaptive=False
    )

    assert limiter.max_concurrent == 5
    assert isinstance(limiter.rate_limiter, TokenBucket)


def test_batch_rate_limiter_acquire_success():
    limiter = BatchRateLimiter(max_concurrent=5, rate_per_second=10.0)

    result = limiter.acquire(timeout=1.0)

    assert result is True


def test_batch_rate_limiter_acquire_timeout_semaphore():
    limiter = BatchRateLimiter(max_concurrent=1, rate_per_second=10.0)

    limiter.semaphore.acquire()

    result = limiter.acquire(timeout=0.01)

    assert result is False

    limiter.semaphore.release()


def test_batch_rate_limiter_acquire_timeout_rate_limit():
    limiter = BatchRateLimiter(
        max_concurrent=5,
        rate_per_second=0.1,
        enable_adaptive=False
    )

    limiter.rate_limiter.tokens = 0

    result = limiter.acquire(timeout=0.01)

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
    limiter = BatchRateLimiter(max_concurrent=5, rate_per_second=1.0)

    start = time.time()
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

    threads = []
    for _ in range(20):
        thread = threading.Thread(target=worker)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    assert len(results) == 20


def test_batch_rate_limiter_exception_handling():
    limiter = BatchRateLimiter(max_concurrent=5, rate_per_second=10.0)

    with patch.object(limiter.rate_limiter, 'acquire_permit', side_effect=Exception("Error")):
        with pytest.raises(Exception):
            limiter.acquire(timeout=1.0)


def test_batch_rate_limiter_acquire_updates_stats():
    limiter = BatchRateLimiter(max_concurrent=5, rate_per_second=10.0)

    limiter.acquire(timeout=1.0)
    limiter.release_success()

    stats = limiter.get_stats()
    assert stats["total_wait_time"] >= 0
    assert stats["max_wait_time"] >= 0


@patch('psutil.Process')
def test_cleanup_memory_success(mock_process):
    mock_memory_info = MagicMock()
    mock_memory_info.rss = 1024 * 1024 * 100
    mock_memory_info.vms = 1024 * 1024 * 200

    mock_proc = MagicMock()
    mock_proc.memory_info.return_value = mock_memory_info
    mock_process.return_value = mock_proc

    result = cleanup_memory()

    assert result is not None
    assert "rss_mb" in result
    assert "vms_mb" in result
    assert result["rss_mb"] == 100.0
    assert result["vms_mb"] == 200.0


@patch('psutil.Process')
def test_cleanup_memory_exception(mock_process):
    mock_process.side_effect = Exception("Error")

    result = cleanup_memory()

    assert result is None


def test_adaptive_rate_limiter_bucket_rate_update():
    limiter = AdaptiveRateLimiter(base_rate=10.0)

    limiter.current_rate = 20.0
    limiter.acquire_permit(timeout=1.0)

    assert limiter.bucket.refill_rate == 20.0


def test_adaptive_rate_limiter_bucket_rate_no_update():
    limiter = AdaptiveRateLimiter(base_rate=10.0)

    initial_rate = limiter.bucket.refill_rate
    limiter.acquire_permit(timeout=1.0)

    assert limiter.bucket.refill_rate == initial_rate


def test_batch_rate_limiter_non_adaptive_release():
    limiter = BatchRateLimiter(
        max_concurrent=5,
        rate_per_second=10.0,
        enable_adaptive=False
    )

    limiter.acquire()
    limiter.release_success()

    assert limiter.stats["files_processed"] == 1


def test_batch_rate_limiter_non_adaptive_error():
    limiter = BatchRateLimiter(
        max_concurrent=5,
        rate_per_second=10.0,
        enable_adaptive=False
    )

    limiter.acquire()
    limiter.release_error()

    assert limiter.stats["files_failed"] == 1


def test_adaptive_rate_limiter_rate_limits():
    limiter = AdaptiveRateLimiter(base_rate=10.0, min_rate=1.0, max_rate=50.0)

    for _ in range(50):
        limiter.record_error()

    limiter._adjust_rate()

    assert limiter.current_rate >= limiter.min_rate

    limiter.current_rate = 5.0
    for _ in range(100):
        limiter.record_success()

    limiter._adjust_rate()

    assert limiter.current_rate <= limiter.max_rate


@patch('psutil.virtual_memory')
@patch('psutil.cpu_percent')
def test_adaptive_rate_limiter_memory_threshold(mock_cpu, mock_memory):
    mock_memory.return_value.percent = 85.0
    mock_cpu.return_value = 60.0

    limiter = AdaptiveRateLimiter(
        base_rate=10.0,
        memory_threshold=0.8
    )

    limiter.last_system_check = 0
    initial_rate = limiter.current_rate
    limiter._check_system_load()

    assert limiter.current_rate < initial_rate


@patch('psutil.virtual_memory')
@patch('psutil.cpu_percent')
def test_adaptive_rate_limiter_cpu_threshold(mock_cpu, mock_memory):
    mock_memory.return_value.percent = 60.0
    mock_cpu.return_value = 95.0

    limiter = AdaptiveRateLimiter(
        base_rate=10.0,
        cpu_threshold=0.9
    )

    limiter.last_system_check = 0
    initial_rate = limiter.current_rate
    limiter._check_system_load()

    assert limiter.current_rate < initial_rate


def test_token_bucket_multiple_acquires():
    bucket = TokenBucket(capacity=10, refill_rate=5.0)

    assert bucket.acquire(tokens=3) is True
    assert bucket.acquire(tokens=3) is True
    assert bucket.acquire(tokens=3) is True

    assert bucket.tokens <= 2.0


def test_adaptive_rate_limiter_recent_window():
    limiter = AdaptiveRateLimiter(base_rate=10.0)

    for _ in range(10):
        limiter.record_success()

    time.sleep(0.1)

    for _ in range(5):
        limiter.record_error()

    stats = limiter.get_stats()

    assert stats["recent_operations"] == 15


def test_batch_rate_limiter_acquire_with_adaptive_failure():
    limiter = BatchRateLimiter(
        max_concurrent=5,
        rate_per_second=10.0,
        enable_adaptive=True
    )

    with patch.object(limiter.rate_limiter, 'acquire_permit', return_value=False):
        result = limiter.acquire(timeout=0.1)
        assert result is False


def test_batch_rate_limiter_acquire_releases_semaphore_on_failure():
    limiter = BatchRateLimiter(
        max_concurrent=2,
        rate_per_second=10.0,
        enable_adaptive=True
    )

    with patch.object(limiter.rate_limiter, 'acquire_permit', return_value=False):
        limiter.acquire(timeout=0.1)

    result = limiter.acquire(timeout=1.0)
    assert result is True


def test_token_bucket_acquire_default_tokens():
    bucket = TokenBucket(capacity=10, refill_rate=5.0)

    result = bucket.acquire()

    assert result is True
    assert bucket.tokens == 9.0


def test_adaptive_rate_limiter_acquire_permit_with_rate_update():
    limiter = AdaptiveRateLimiter(base_rate=5.0)

    for _ in range(50):
        limiter.record_success()

    limiter._adjust_rate()

    result = limiter.acquire_permit(timeout=1.0)
    assert result is True


def test_batch_rate_limiter_get_stats_with_adaptive():
    limiter = BatchRateLimiter(
        max_concurrent=5,
        rate_per_second=10.0,
        enable_adaptive=True
    )

    limiter.acquire()
    limiter.release_success()

    stats = limiter.get_stats()

    assert "current_rate" in stats
    assert "base_rate" in stats
    assert "recent_operations" in stats
