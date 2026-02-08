from __future__ import annotations

import time

import pytest

import r2inspect.utils.rate_limiter as rate_limiter
from r2inspect.utils.rate_limiter import AdaptiveRateLimiter, BatchRateLimiter


class _BadPsutil:
    @staticmethod
    def virtual_memory() -> object:
        raise RuntimeError("boom")

    @staticmethod
    def cpu_percent(interval: float = 0.0) -> float:
        raise RuntimeError("boom")


def test_adaptive_rate_limiter_updates_bucket_rate() -> None:
    limiter = AdaptiveRateLimiter(base_rate=1.0, max_rate=2.0, min_rate=0.1)
    limiter.last_system_check = time.time()
    limiter.current_rate = 1.5
    limiter.bucket.refill_rate = 1.0

    limiter.acquire_permit(timeout=0.01)
    assert limiter.bucket.refill_rate == limiter.current_rate


def test_adaptive_rate_limiter_system_check_exception_path() -> None:
    limiter = AdaptiveRateLimiter(base_rate=1.0, max_rate=2.0, min_rate=0.1)
    limiter.last_system_check = 0.0
    old_psutil = rate_limiter.psutil
    try:
        rate_limiter.psutil = _BadPsutil()
        limiter._check_system_load()
        assert limiter.current_rate <= limiter.base_rate
    finally:
        rate_limiter.psutil = old_psutil


def test_batch_rate_limiter_acquire_paths() -> None:
    limiter = BatchRateLimiter(max_concurrent=0, rate_per_second=1.0, burst_size=1)
    assert limiter.acquire(timeout=0.01) is False

    limiter = BatchRateLimiter(
        max_concurrent=1, rate_per_second=1.0, burst_size=0, enable_adaptive=False
    )
    assert limiter.acquire(timeout=0.01) is False


def test_batch_rate_limiter_exception_release_and_stats() -> None:
    limiter = BatchRateLimiter(max_concurrent=1, rate_per_second=1.0, burst_size=1)
    assert limiter.get_stats()["success_rate"] == 0.0

    limiter.release_error("err")
    stats = limiter.get_stats()
    assert stats["files_failed"] == 1

    limiter.rate_limiter.bucket = None  # force acquire_permit failure
    with pytest.raises(AttributeError):
        limiter.acquire(timeout=0.01)
