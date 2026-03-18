#!/usr/bin/env python3
"""Batch lifecycle and shutdown helpers."""

from __future__ import annotations

from typing import Any

from rich.console import Console

from . import batch_runtime as _batch_runtime


def setup_rate_limiter(
    threads: int,
    verbose: bool,
    console: Console,
    *,
    cap_threads_fn: Any | None = None,
) -> Any:
    """Setup rate limiter for batch processing."""
    kwargs = {}
    if cap_threads_fn is not None:
        kwargs["cap_threads_fn"] = cap_threads_fn
    return _batch_runtime.setup_rate_limiter(threads, verbose, console, **kwargs)


def safe_exit(code: int = 0) -> None:
    """Exit via the batch runtime helper."""
    _batch_runtime._safe_exit(code)


def ensure_shutdown(timeout: float = 2.0) -> None:
    """Ensure batch execution does not hang on lingering non-daemon threads."""
    _batch_runtime.ensure_batch_shutdown(timeout)


def schedule_exit(delay: float = 2.0) -> None:
    """Schedule a forced process exit to prevent batch hangs."""
    _batch_runtime.schedule_forced_exit(delay)


def flush_coverage_data() -> None:
    """Persist coverage data when running under coverage."""
    _batch_runtime._flush_coverage_data()


def pytest_running() -> bool:
    """Detect pytest runtime to avoid stopping coverage from background threads."""
    return _batch_runtime._pytest_running()
