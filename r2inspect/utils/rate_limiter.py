#!/usr/bin/env python3
"""
Rate limiting utilities for r2inspect batch processing
"""

import gc
import os
import threading
import time
from collections import deque
from typing import Any

import psutil


class TokenBucket:
    """Thread-safe token bucket rate limiter"""

    def __init__(self, capacity: int, refill_rate: float):
        """
        Initialize token bucket

        Args:
            capacity: Maximum number of tokens
            refill_rate: Tokens per second refill rate
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def acquire(self, tokens: int = 1, timeout: float | None = None) -> bool:
        """
        Acquire tokens from bucket

        Args:
            tokens: Number of tokens to acquire
            timeout: Maximum time to wait for tokens

        Returns:
            True if tokens acquired, False if timeout
        """
        start_time = time.time()

        while True:
            with self.lock:
                self._refill()

                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True

            # Check timeout
            if timeout is not None:
                elapsed = time.time() - start_time
                if elapsed >= timeout:
                    return False

            # Small sleep to prevent busy waiting
            time.sleep(0.01)

    def _refill(self):
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self.last_refill

        # Add tokens based on elapsed time
        new_tokens = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + new_tokens)
        self.last_refill = now


class AdaptiveRateLimiter:
    """Adaptive rate limiter that adjusts based on system load and errors"""

    def __init__(
        self,
        base_rate: float = 5.0,  # Files per second
        max_rate: float = 20.0,
        min_rate: float = 0.5,
        memory_threshold: float = 0.8,  # 80% memory usage
        cpu_threshold: float = 0.9,
    ):  # 90% CPU usage
        self.base_rate = base_rate
        self.max_rate = max_rate
        self.min_rate = min_rate
        self.memory_threshold = memory_threshold
        self.cpu_threshold = cpu_threshold

        # Current rate
        self.current_rate = base_rate

        # Error tracking
        self.error_window: deque[float] = deque(maxlen=100)  # Last 100 operations
        self.success_window: deque[float] = deque(maxlen=100)

        # System monitoring
        self.last_system_check = time.time()
        self.system_check_interval = 5.0  # Check every 5 seconds

        # Thread safety
        self.lock = threading.Lock()

        # Create token bucket
        self.bucket = TokenBucket(capacity=int(base_rate * 10), refill_rate=base_rate)

    def acquire_permit(self, timeout: float | None = 30.0) -> bool:
        """
        Acquire permission to process a file

        Args:
            timeout: Maximum time to wait for permit

        Returns:
            True if permit acquired, False if timeout
        """
        # Check system load and adjust rate
        self._check_system_load()

        # Update bucket rate if needed
        with self.lock:
            if abs(self.bucket.refill_rate - self.current_rate) > 0.1:
                self.bucket.refill_rate = self.current_rate

        return self.bucket.acquire(tokens=1, timeout=timeout)

    def record_success(self):
        """Record successful operation"""
        with self.lock:
            self.success_window.append(time.time())
            self._adjust_rate()

    def record_error(self, _error_type: str = "unknown"):
        """Record failed operation"""
        with self.lock:
            self.error_window.append(time.time())
            self._adjust_rate()

    def _check_system_load(self):
        """Check system load and adjust rate accordingly"""
        now = time.time()

        if now - self.last_system_check < self.system_check_interval:
            return

        self.last_system_check = now

        try:
            # Check memory usage
            memory_percent = psutil.virtual_memory().percent / 100.0

            # Check CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1) / 100.0

            with self.lock:
                # Reduce rate if system is under stress
                if memory_percent > self.memory_threshold or cpu_percent > self.cpu_threshold:
                    self.current_rate = max(self.min_rate, self.current_rate * 0.7)
                elif memory_percent < 0.6 and cpu_percent < 0.7:
                    # Increase rate if system has capacity
                    self.current_rate = min(self.max_rate, self.current_rate * 1.1)

        except Exception:
            # If we can't check system load, be conservative
            with self.lock:
                self.current_rate = max(self.min_rate, self.current_rate * 0.9)

    def _adjust_rate(self):
        """Adjust rate based on recent error rate"""
        now = time.time()
        recent_window = 60.0  # Look at last 60 seconds

        # Count recent errors and successes
        recent_errors = sum(1 for t in self.error_window if now - t < recent_window)
        recent_successes = sum(1 for t in self.success_window if now - t < recent_window)

        total_recent = recent_errors + recent_successes

        if total_recent < 5:
            return  # Not enough data

        error_rate = recent_errors / total_recent

        # Adjust rate based on error rate
        if error_rate > 0.3:  # High error rate
            self.current_rate = max(self.min_rate, self.current_rate * 0.5)
        elif error_rate > 0.1:  # Moderate error rate
            self.current_rate = max(self.min_rate, self.current_rate * 0.8)
        elif error_rate < 0.05:  # Low error rate
            self.current_rate = min(self.max_rate, self.current_rate * 1.2)

    def get_stats(self) -> dict[str, Any]:
        """Get current rate limiter statistics"""
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
    """Rate limiter specifically designed for batch processing"""

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

        # Statistics
        self.stats = {
            "files_processed": 0,
            "files_failed": 0,
            "total_wait_time": 0.0,
            "max_wait_time": 0.0,
        }
        self.stats_lock = threading.Lock()

    def acquire(self, timeout: float | None = 60.0) -> bool:
        """
        Acquire permission to process a file

        Args:
            timeout: Maximum time to wait

        Returns:
            True if permission granted, False if timeout
        """
        start_time = time.time()

        # First, acquire concurrency semaphore
        if not self.semaphore.acquire(timeout=timeout):
            return False

        try:
            # Then, acquire rate limit permission
            remaining_timeout = None
            if timeout:
                elapsed = time.time() - start_time
                remaining_timeout = max(0, timeout - elapsed)

            if isinstance(self.rate_limiter, AdaptiveRateLimiter):
                success = self.rate_limiter.acquire_permit(timeout=remaining_timeout)
            else:
                success = self.rate_limiter.acquire(tokens=1, timeout=remaining_timeout)

            if success:
                # Update statistics
                wait_time = time.time() - start_time
                with self.stats_lock:
                    self.stats["total_wait_time"] += wait_time
                    self.stats["max_wait_time"] = max(self.stats["max_wait_time"], wait_time)

                return True
            else:
                # Release semaphore if rate limit failed
                self.semaphore.release()
                return False

        except Exception:
            # Release semaphore on any error
            self.semaphore.release()
            raise

    def release_success(self):
        """Release after successful processing"""
        if isinstance(self.rate_limiter, AdaptiveRateLimiter):
            self.rate_limiter.record_success()

        with self.stats_lock:
            self.stats["files_processed"] += 1

        self.semaphore.release()

    def release_error(self, error_type: str = "unknown"):
        """Release after failed processing"""
        if isinstance(self.rate_limiter, AdaptiveRateLimiter):
            self.rate_limiter.record_error(error_type)

        with self.stats_lock:
            self.stats["files_failed"] += 1

        self.semaphore.release()

    def get_stats(self) -> dict[str, Any]:
        """Get rate limiter statistics"""
        with self.stats_lock:
            base_stats = self.stats.copy()

        if isinstance(self.rate_limiter, AdaptiveRateLimiter):
            rate_stats = self.rate_limiter.get_stats()
            base_stats.update(rate_stats)

        # Add calculated metrics
        total_files = base_stats["files_processed"] + base_stats["files_failed"]
        if total_files > 0:
            base_stats["success_rate"] = base_stats["files_processed"] / total_files
            base_stats["avg_wait_time"] = base_stats["total_wait_time"] / total_files
        else:
            base_stats["success_rate"] = 0.0
            base_stats["avg_wait_time"] = 0.0

        return base_stats


def cleanup_memory():
    """Force garbage collection to free memory"""
    gc.collect()

    # Try to get memory info if available
    try:
        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()
        return {
            "rss_mb": memory_info.rss / 1024 / 1024,
            "vms_mb": memory_info.vms / 1024 / 1024,
        }
    except Exception:
        return None
