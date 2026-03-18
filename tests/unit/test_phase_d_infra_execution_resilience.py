#!/usr/bin/env python3
"""Resilience-focused regression tests for execution utilities (Fase D).

NO mocks, NO @patch. Uses real objects, monkeypatch, and SimpleNamespace stubs.
"""

from __future__ import annotations

from types import SimpleNamespace

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


def test_memory_manager_gc_trigger_and_error_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monitor = MemoryMonitor(
        MemoryLimits(
            max_process_memory_mb=4.0,
            memory_warning_threshold=0.95,
            memory_critical_threshold=0.99,
            gc_trigger_threshold=0.70,
        )
    )

    # Force branch that only triggers _trigger_gc() and keeps status as normal.
    monitor.process = SimpleNamespace(
        memory_info=lambda: SimpleNamespace(rss=int(0.78 * 4.0 * 1024 * 1024))
    )
    monitor.system_memory = SimpleNamespace(
        total=8 * 1024 * 1024 * 1024,
        available=4 * 1024 * 1024 * 1024,
        percent=20.0,
    )
    trigger_calls: list[bool] = []
    original_trigger = monitor._trigger_gc

    try:
        monitor._trigger_gc = lambda aggressive=False: trigger_calls.append(aggressive)  # type: ignore[method-assign]
        monkeypatch.setattr(memory_module.psutil, "virtual_memory", lambda: monitor.system_memory)
        stats = monitor.check_memory(force=True)

        assert stats["status"] == "normal"
        assert trigger_calls == [False]
    finally:
        monitor._trigger_gc = original_trigger

    # Force error handling path returning error stats.
    monitor.process = SimpleNamespace(
        memory_info=lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    error_stats = monitor.check_memory(force=True)
    cached_stats = monitor._get_cached_stats()
    assert error_stats["status"] in ("error", "unknown")
    assert cached_stats["status"] in ("error", "unknown")


def test_memory_manager_callbacks_swallow_exceptions(monkeypatch: pytest.MonkeyPatch) -> None:
    monitor = MemoryMonitor(
        MemoryLimits(
            max_process_memory_mb=1.0,
            memory_warning_threshold=0.80,
            memory_critical_threshold=0.90,
            gc_trigger_threshold=0.70,
        )
    )

    monitor.process = SimpleNamespace(
        memory_info=lambda: SimpleNamespace(rss=int(0.82 * 1024 * 1024))
    )
    monitor.system_memory = SimpleNamespace(
        total=2 * 1024 * 1024 * 1024,
        available=1 * 1024 * 1024 * 1024,
        percent=20.0,
    )
    monkeypatch.setattr(memory_module.psutil, "virtual_memory", lambda: monitor.system_memory)
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


def test_rate_limiter_cleanup_memory_error_path(monkeypatch: pytest.MonkeyPatch) -> None:
    import r2inspect.infrastructure.rate_limiter as rl_mod

    monkeypatch.setattr(
        rl_mod.psutil, "Process", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("no psutil"))
    )
    assert cleanup_memory() is None


def test_batch_rate_limiter_acquire_handles_rate_limit_exception() -> None:
    limiter = BatchRateLimiter(max_concurrent=1, rate_per_second=2.0, enable_adaptive=False)

    # Save original acquire method and replace with one that raises
    original_acquire = limiter.rate_limiter.acquire

    def _failing_acquire(*args, **kwargs):
        raise RuntimeError("rate fail")

    limiter.rate_limiter.acquire = _failing_acquire
    try:
        with pytest.raises(RuntimeError, match="rate fail"):
            limiter.acquire(timeout=0.1)
    finally:
        limiter.rate_limiter.acquire = original_acquire

    # After release in exception handler, semaphore should be reusable.
    assert limiter.acquire(timeout=0.1) is True


def test_adaptive_rate_limiter_updates_rate_from_system_stress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import r2inspect.infrastructure.rate_limiter as rl_mod

    limiter = AdaptiveRateLimiter(base_rate=4.0, max_rate=10.0, min_rate=1.0)
    limiter.last_system_check = 0
    monkeypatch.setattr(rl_mod.psutil, "virtual_memory", lambda: SimpleNamespace(percent=95.0))
    monkeypatch.setattr(rl_mod.psutil, "cpu_percent", lambda: 95.0)
    limiter._check_system_load()

    assert limiter.current_rate < 4.0
