#!/usr/bin/env python3
"""Rate limiting utilities for batch processing."""

from __future__ import annotations

import gc
import os
import threading
import time
import warnings
from collections import deque
from typing import Any

import psutil

from .logging import get_logger

logger = get_logger(__name__)


class TokenBucket:
    """Thread-safe token bucket rate limiter."""

    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens: float = float(capacity)
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def acquire(self, tokens: int = 1, timeout: float | None = None) -> bool:
        start_time = time.time()
        while True:
            with self.lock:
                self._refill()
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True
            if timeout is not None and (time.time() - start_time) >= timeout:
                return False
            time.sleep(0.01)

    def _refill(self) -> None:
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(float(self.capacity), self.tokens + (elapsed * self.refill_rate))
        self.last_refill = now


class AdaptiveRateLimiter:
    """Adaptive rate limiter that adjusts based on system load and errors."""

    def __init__(
        self,
        base_rate: float = 5.0,
        max_rate: float = 20.0,
        min_rate: float = 0.5,
        memory_threshold: float = 0.8,
        cpu_threshold: float = 0.9,
    ):
        self.base_rate = base_rate
        self.max_rate = max_rate
        self.min_rate = min_rate
        self.memory_threshold = memory_threshold
        self.cpu_threshold = cpu_threshold
        self.current_rate = base_rate
        self.error_window: deque[float] = deque(maxlen=100)
        self.success_window: deque[float] = deque(maxlen=100)
        self.last_system_check = time.time()
        self.system_check_interval = 5.0
        self.lock = threading.Lock()
        self.bucket = TokenBucket(capacity=int(base_rate * 10), refill_rate=base_rate)

    def acquire_permit(self, timeout: float | None = 30.0) -> bool:
        self._check_system_load()
        with self.lock:
            if abs(self.bucket.refill_rate - self.current_rate) > 0.1:
                self.bucket.refill_rate = self.current_rate
        return self.bucket.acquire(tokens=1, timeout=timeout)

    def record_success(self) -> None:
        with self.lock:
            self.success_window.append(time.time())
            self._adjust_rate()

    def record_error(self, _error_type: str = "unknown") -> None:
        with self.lock:
            self.error_window.append(time.time())
            self._adjust_rate()

    def _check_system_load(self) -> None:
        now = time.time()
        if now - self.last_system_check < self.system_check_interval:
            return
        self.last_system_check = now
        try:
            memory_percent = psutil.virtual_memory().percent / 100.0
            cpu_percent = psutil.cpu_percent(interval=0.1) / 100.0
            with self.lock:
                if memory_percent > self.memory_threshold or cpu_percent > self.cpu_threshold:
                    self.current_rate = max(self.min_rate, self.current_rate * 0.7)
                elif memory_percent < 0.6 and cpu_percent < 0.7:
                    self.current_rate = min(self.max_rate, self.current_rate * 1.1)
        except Exception as exc:
            logger.debug("Adaptive rate limiter system-load check failed: %s", exc)
            with self.lock:
                self.current_rate = max(self.min_rate, self.current_rate * 0.9)

    def _adjust_rate(self) -> None:
        now = time.time()
        recent_window = 60.0
        recent_errors = sum(1 for t in self.error_window if now - t < recent_window)
        recent_successes = sum(1 for t in self.success_window if now - t < recent_window)
        total_recent = recent_errors + recent_successes
        if total_recent < 5:
            return
        error_rate = recent_errors / total_recent
        if error_rate > 0.3:
            self.current_rate = max(self.min_rate, self.current_rate * 0.5)
        elif error_rate > 0.1:
            self.current_rate = max(self.min_rate, self.current_rate * 0.8)
        elif error_rate < 0.05:
            self.current_rate = min(self.max_rate, self.current_rate * 1.2)

    def get_stats(self) -> dict[str, Any]:
        with self.lock:
            now = time.time()
            recent_window = 60.0
            recent_errors = sum(1 for t in self.error_window if now - t < recent_window)
            recent_successes = sum(1 for t in self.success_window if now - t < recent_window)
            total_recent = recent_errors + recent_successes
            return {
                "current_rate": self.current_rate,
                "base_rate": self.base_rate,
                "recent_operations": total_recent,
                "recent_errors": recent_errors,
                "recent_error_rate": recent_errors / max(1, total_recent),
                "tokens_available": self.bucket.tokens,
                "bucket_capacity": self.bucket.capacity,
            }


class BatchRateLimiter:
    """Rate limiter specifically designed for batch processing."""

    def __init__(
        self,
        max_concurrent: int = 10,
        rate_per_second: float = 5.0,
        burst_size: int = 20,
        enable_adaptive: bool = True,
    ):
        self.max_concurrent = max_concurrent
        self.semaphore = threading.Semaphore(max_concurrent)
        if enable_adaptive:
            self.rate_limiter: AdaptiveRateLimiter | TokenBucket = AdaptiveRateLimiter(
                base_rate=rate_per_second,
                max_rate=rate_per_second * 2,
                min_rate=rate_per_second * 0.1,
            )
        else:
            self.rate_limiter = TokenBucket(capacity=burst_size, refill_rate=rate_per_second)
        self.adaptive = enable_adaptive
        self.stats = {
            "files_processed": 0,
            "files_failed": 0,
            "total_wait_time": 0.0,
            "max_wait_time": 0.0,
        }
        self.stats_lock = threading.Lock()

    def acquire(self, timeout: float | None = 60.0) -> bool:
        start_time = time.time()
        if not self.semaphore.acquire(timeout=timeout):
            return False
        try:
            remaining_timeout = None
            if timeout:
                remaining_timeout = max(0, timeout - (time.time() - start_time))
            if isinstance(self.rate_limiter, AdaptiveRateLimiter):
                success = self.rate_limiter.acquire_permit(timeout=remaining_timeout)
            else:
                success = self.rate_limiter.acquire(tokens=1, timeout=remaining_timeout)
            if success:
                wait_time = time.time() - start_time
                with self.stats_lock:
                    self.stats["total_wait_time"] += wait_time
                    self.stats["max_wait_time"] = max(self.stats["max_wait_time"], wait_time)
                return True
            self.semaphore.release()
            return False
        except Exception as exc:
            logger.debug("Batch rate limiter acquire failed, releasing semaphore: %s", exc)
            self.semaphore.release()
            raise

    def release_success(self) -> None:
        if isinstance(self.rate_limiter, AdaptiveRateLimiter):
            self.rate_limiter.record_success()
        with self.stats_lock:
            self.stats["files_processed"] += 1
        self.semaphore.release()

    def release_error(self, error_type: str = "unknown") -> None:
        if isinstance(self.rate_limiter, AdaptiveRateLimiter):
            self.rate_limiter.record_error(error_type)
        with self.stats_lock:
            self.stats["files_failed"] += 1
        self.semaphore.release()

    def get_stats(self) -> dict[str, Any]:
        with self.stats_lock:
            base_stats = self.stats.copy()
        if isinstance(self.rate_limiter, AdaptiveRateLimiter):
            base_stats.update(self.rate_limiter.get_stats())
        total_files = base_stats["files_processed"] + base_stats["files_failed"]
        if total_files > 0:
            base_stats["success_rate"] = base_stats["files_processed"] / total_files
            base_stats["avg_wait_time"] = base_stats["total_wait_time"] / total_files
        else:
            base_stats["success_rate"] = 0.0
            base_stats["avg_wait_time"] = 0.0
        return base_stats


def cleanup_memory() -> dict[str, float] | None:
    """Force garbage collection to free memory."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ResourceWarning)
        gc.collect()
    try:
        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()
        return {
            "rss_mb": memory_info.rss / 1024 / 1024,
            "vms_mb": memory_info.vms / 1024 / 1024,
        }
    except Exception as exc:
        logger.debug("Memory cleanup metrics unavailable: %s", exc)
        return None


__all__ = ["AdaptiveRateLimiter", "BatchRateLimiter", "TokenBucket", "cleanup_memory"]
