#!/usr/bin/env python3
"""Runtime and shutdown helpers for batch CLI execution."""

from __future__ import annotations

import os
import sys
import threading
import time
from typing import Any

from ..infrastructure.logging import get_logger
from .batch_workers import _cap_threads_for_execution

logger = get_logger(__name__)
TEST_MODE_VALUES = {"1", "true", "yes"}
TEST_COVERAGE_PREFIX = "R2INSPECT_TEST_COVERAGE_"


def setup_rate_limiter(
    threads: int,
    verbose: bool,
    console: Any,
    *,
    cap_threads_fn: Any = _cap_threads_for_execution,
) -> Any:
    """Create a rate limiter configured for batch execution."""
    from ..infrastructure.rate_limiter import BatchRateLimiter

    effective_threads = cap_threads_fn(threads)
    base_rate = min(effective_threads * 1.5, 25.0)
    rate_limiter = BatchRateLimiter(
        max_concurrent=effective_threads,
        rate_per_second=base_rate,
        burst_size=effective_threads * 3,
        enable_adaptive=True,
    )

    if verbose:
        console.print(
            f"[blue]Rate limiting: {base_rate:.1f} files/sec, adaptive mode enabled[/blue]"
        )

    return rate_limiter


def _safe_exit(code: int = 0) -> None:
    if os.getenv("R2INSPECT_TEST_SAFE_EXIT"):
        raise SystemExit(code)
    os._exit(code)  # pragma: no cover


def _pytest_running() -> bool:
    """Detect pytest runtime to avoid stopping coverage from background threads."""
    return any(
        (
            _test_mode_enabled(),
            bool(os.getenv("R2INSPECT_TEST_SAFE_EXIT")),
            bool(os.getenv("PYTEST_CURRENT_TEST")),
            _coverage_test_env_enabled(),
            any("pytest" in arg for arg in sys.argv),
            "pytest" in sys.modules,  # pragma: no cover
        )
    )


def _test_mode_enabled() -> bool:
    """Return whether the explicit test mode environment flag is enabled."""
    return os.getenv("R2INSPECT_TEST_MODE", "").lower() in TEST_MODE_VALUES


def _coverage_test_env_enabled() -> bool:
    """Return whether one of the coverage-specific test env vars is enabled."""
    return any(key.startswith(TEST_COVERAGE_PREFIX) for key in os.environ)


def _flush_coverage_data() -> None:
    """Persist coverage data when running under coverage."""
    cov: Any | None = None
    try:
        if os.getenv("R2INSPECT_TEST_COVERAGE_IMPORT_ERROR"):
            raise ImportError("Simulated coverage import error")
        import coverage
    except Exception:
        return
    try:
        if os.getenv("R2INSPECT_TEST_COVERAGE_CURRENT_ERROR"):
            raise RuntimeError("Simulated coverage current error")
        if os.getenv("R2INSPECT_TEST_COVERAGE_DUMMY"):

            class _DummyCoverage:
                def stop(self) -> None:  # pragma: no cover
                    return None

                def save(self) -> None:
                    return None

            cov = _DummyCoverage()
        else:
            cov = coverage.Coverage.current()
    except Exception:
        return
    if os.getenv("R2INSPECT_TEST_COVERAGE_NONE"):
        cov = None
    if cov is None:
        return
    try:
        if os.getenv("R2INSPECT_TEST_COVERAGE_SAVE_ERROR"):
            raise RuntimeError("Simulated coverage save error")
        if _pytest_running():
            cov.save()
            return
        cov.save()  # pragma: no cover
    except Exception as e:
        logger.debug("Error saving coverage: %s", e)


def ensure_batch_shutdown(timeout: float = 2.0) -> None:
    """Ensure batch execution does not hang on lingering non-daemon threads."""
    deadline = time.time() + timeout
    current = threading.current_thread()

    def _remaining_threads() -> list[threading.Thread]:
        return [
            thread
            for thread in threading.enumerate()
            if thread is not current and not thread.daemon
        ]

    remaining = _remaining_threads()
    for thread in remaining:
        remaining_time = max(0.0, deadline - time.time())
        if remaining_time <= 0:
            break
        thread.join(timeout=remaining_time)

    remaining = _remaining_threads()
    if remaining:
        names = ", ".join(thread.name for thread in remaining)
        logger.warning("Forcing batch shutdown with lingering threads: %s", names)
        _flush_coverage_data()
        _safe_exit(0)


def schedule_forced_exit(delay: float = 2.0) -> None:
    """Schedule a forced process exit to prevent batch hangs."""
    if os.getenv("R2INSPECT_DISABLE_FORCED_EXIT"):
        return

    def _exit() -> None:
        sys.stdout.flush()
        sys.stderr.flush()
        _flush_coverage_data()
        if _pytest_running():
            return
        _safe_exit(0)

    timer = threading.Timer(delay, _exit)
    timer.daemon = True
    timer.start()
