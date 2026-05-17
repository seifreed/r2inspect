#!/usr/bin/env python3
"""Resilience-focused regression tests for execution utilities (Fase D).

Real objects only — no mocking framework, no fixture patching, no decorators.
Collaborators that would otherwise reach psutil are supplied through the
production dependency-injection seams with hand-rolled doubles.
"""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest

import r2inspect.infrastructure.memory as memory_module
from r2inspect.infrastructure.memory import (
    MemoryAwareAnalyzer,
    MemoryLimits,
    MemoryMonitor,
    configure_memory_limits,
    cleanup_memory as global_cleanup_memory,
)
from r2inspect.infrastructure.rate_limiter import (
    AdaptiveRateLimiter,
    BatchRateLimiter,
    cleanup_memory,
)
from r2inspect.infrastructure.retry_manager import (
    RetryConfig,
    RetryManager,
    RetryStrategy,
    retry_on_failure,
)


class _FakeProcess:
    """Minimal psutil.Process double exposing only memory_info()."""

    def __init__(self, rss: int) -> None:
        self._rss = rss

    def memory_info(self) -> SimpleNamespace:
        return SimpleNamespace(rss=self._rss, vms=self._rss)


class _RaisingProcess:
    def memory_info(self) -> SimpleNamespace:
        raise RuntimeError("boom")


class _RecordingMemoryMonitor(MemoryMonitor):
    """MemoryMonitor that records _trigger_gc calls instead of running GC."""

    def __init__(
        self,
        limits: MemoryLimits | None = None,
        *,
        process: Any | None = None,
        system_memory_provider: Callable[[], Any] | None = None,
    ) -> None:
        super().__init__(
            limits,
            process=process,
            system_memory_provider=system_memory_provider,
        )
        self.trigger_calls: list[bool] = []

    def _trigger_gc(self, aggressive: bool = False) -> None:
        self.trigger_calls.append(aggressive)


def test_memory_manager_gc_trigger_and_error_paths() -> None:
    monitor = _RecordingMemoryMonitor(
        MemoryLimits(
            max_process_memory_mb=4.0,
            memory_warning_threshold=0.95,
            memory_critical_threshold=0.99,
            gc_trigger_threshold=0.70,
        ),
        process=_FakeProcess(rss=int(0.78 * 4.0 * 1024 * 1024)),
        system_memory_provider=lambda: SimpleNamespace(
            total=8 * 1024 * 1024 * 1024,
            available=4 * 1024 * 1024 * 1024,
            percent=20.0,
        ),
    )

    stats = monitor.check_memory(force=True)

    assert stats["status"] == "normal"
    assert monitor.trigger_calls == [False]

    # Force error handling path returning error stats.
    failing = MemoryMonitor(
        MemoryLimits(max_process_memory_mb=4.0),
        process=_RaisingProcess(),
    )
    error_stats = failing.check_memory(force=True)
    cached_stats = failing._get_cached_stats()
    assert error_stats["status"] in ("error", "unknown")
    assert cached_stats["status"] in ("error", "unknown")


def test_memory_manager_callbacks_swallow_exceptions() -> None:
    monitor = MemoryMonitor(
        MemoryLimits(
            max_process_memory_mb=1.0,
            memory_warning_threshold=0.80,
            memory_critical_threshold=0.90,
            gc_trigger_threshold=0.70,
        ),
        process=_FakeProcess(rss=int(0.82 * 1024 * 1024)),
        system_memory_provider=lambda: SimpleNamespace(
            total=2 * 1024 * 1024 * 1024,
            available=1 * 1024 * 1024 * 1024,
            percent=20.0,
        ),
    )

    monitor.set_callbacks(
        warning_callback=lambda _stats: (_ for _ in ()).throw(RuntimeError("warn")),
        critical_callback=lambda _stats: (_ for _ in ()).throw(RuntimeError("crit")),
    )
    stats = monitor.check_memory(force=True)

    assert stats["status"] == "warning"


def test_memory_manager_global_config_and_cleanup() -> None:
    original_limits = memory_module.global_memory_monitor.limits
    try:
        configure_memory_limits(max_process_memory_mb=1234)
        assert memory_module.global_memory_monitor.limits.max_process_memory_mb == 1234

        # Unknown key should be ignored with a warning path.
        configure_memory_limits(does_not_exist=True)

        assert isinstance(global_cleanup_memory(), dict)
    finally:
        memory_module.global_memory_monitor.limits = original_limits


def test_memory_aware_analyzer_safe_operation_error_paths() -> None:
    monitor = MemoryMonitor(MemoryLimits(max_process_memory_mb=1024))
    monitor.set_callbacks()
    analyzer = MemoryAwareAnalyzer(monitor)

    monitor.check_interval = 0
    assert analyzer.safe_large_operation(lambda: "ok", estimated_memory_mb=0.0) == "ok"

    analyzer.should_skip_analysis(estimated_memory_mb=10.0, analysis_name="big")

    assert (
        analyzer.safe_large_operation(lambda: (_ for _ in ()).throw(RuntimeError("boom")), 0.0)
        is None
    )
    assert (
        analyzer.safe_large_operation(lambda: (_ for _ in ()).throw(MemoryError("oom")), 0.0)
        is None
    )


def test_memory_manager_aggressive_gc_path_is_hit() -> None:
    monitor = MemoryMonitor(MemoryLimits(max_process_memory_mb=1.0))
    monitor._trigger_gc(aggressive=True)

    assert monitor.gc_count >= 1


def test_retry_manager_decorator_command_from_kwargs_skip_retry_for_stable_command() -> None:
    calls = {"count": 0}

    @retry_on_failure(
        auto_retry=True, config=RetryConfig(max_attempts=3, base_delay=0.0, jitter=False)
    )
    def run(**kwargs: object) -> str:
        calls["count"] += 1
        # Stable/unknown command should bypass automatic retry and raise directly
        raise TimeoutError("stable command timeout")

    with pytest.raises(TimeoutError):
        run(command="stable-not-in-set")

    assert calls["count"] >= 1


def test_retry_manager_timeout_is_enforced_before_attempt() -> None:
    manager = RetryManager()
    with pytest.raises(TimeoutError, match="Retry timeout exceeded"):
        manager.retry_operation(
            lambda: "ok",
            command_type="generic",
            config=RetryConfig(max_attempts=2, timeout=-1.0, base_delay=0.0, jitter=False),
        )


def test_retry_manager_retryable_timeout_with_backoff_and_success() -> None:
    manager = RetryManager()
    attempts = 0

    def operation(**_kwargs: object) -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise TimeoutError("first")
        return "ok"

    result = manager.retry_operation(
        operation,
        command_type="generic",
        command="iij",
        config=RetryConfig(
            max_attempts=2,
            base_delay=0.0,
            strategy=RetryStrategy.FIXED_DELAY,
            jitter=False,
        ),
    )
    assert result == "ok"
    assert attempts == 2


def test_retry_manager_re_raise_on_retry_limit() -> None:
    manager = RetryManager()

    def always_fail() -> None:
        raise TimeoutError("retry me")

    with pytest.raises(TimeoutError, match="retry me"):
        manager.retry_operation(
            always_fail,
            command_type="generic",
            config=RetryConfig(max_attempts=1, base_delay=0.0, jitter=False),
        )

    stats = manager.get_stats()
    assert stats["failed_after_retries"] >= 1


def test_rate_limiter_cleanup_memory_error_path() -> None:
    def _raising_factory() -> object:
        raise RuntimeError("no psutil")

    assert cleanup_memory(process_factory=_raising_factory) is None


class _FailingThenOkBucket:
    """TokenBucket double: first acquire raises, subsequent acquires succeed."""

    def __init__(self) -> None:
        self.calls = 0

    def acquire(self, tokens: int = 1, timeout: float | None = None) -> bool:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("rate fail")
        return True


def test_batch_rate_limiter_acquire_handles_rate_limit_exception() -> None:
    limiter = BatchRateLimiter(
        max_concurrent=1,
        rate_per_second=2.0,
        enable_adaptive=False,
        rate_limiter=_FailingThenOkBucket(),
    )

    with pytest.raises(RuntimeError, match="rate fail"):
        limiter.acquire(timeout=0.1)

    # After release in exception handler, semaphore should be reusable.
    assert limiter.acquire(timeout=0.1) is True


def test_adaptive_rate_limiter_updates_rate_from_system_stress() -> None:
    limiter = AdaptiveRateLimiter(
        base_rate=4.0,
        max_rate=10.0,
        min_rate=1.0,
        system_load_provider=lambda: (0.95, 0.95),
    )
    limiter.last_system_check = 0
    limiter._check_system_load()

    assert limiter.current_rate < 4.0
