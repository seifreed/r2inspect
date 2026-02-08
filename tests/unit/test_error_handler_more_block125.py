from __future__ import annotations

from r2inspect.utils.error_handler import (
    ErrorCategory,
    error_handler,
    get_error_stats,
    reset_error_stats,
    safe_execute,
)


def test_error_handler_r2pipe_recovery_and_stats():
    reset_error_stats()

    @error_handler(category=ErrorCategory.R2PIPE, context={"command": "ij"})
    def _boom():
        raise RuntimeError("r2pipe failure")

    result = _boom()
    assert result is None

    stats = get_error_stats()
    assert stats["total_errors"] >= 1
    assert stats["errors_by_category"].get(ErrorCategory.R2PIPE) == 1


def test_safe_execute_uses_recovery_strategy():
    reset_error_stats()

    def _raise():
        raise FileNotFoundError("missing")

    result = safe_execute(_raise, fallback_result="fallback")
    # file access recovery returns None
    assert result is None
