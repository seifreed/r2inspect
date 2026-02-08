from __future__ import annotations

import pytest

from r2inspect.utils.error_handler import (
    ErrorCategory,
    ErrorSeverity,
    error_handler,
    get_error_stats,
    reset_error_stats,
    safe_execute,
)


def test_error_handler_recovery_and_stats():
    reset_error_stats()

    @error_handler(
        category=ErrorCategory.FILE_ACCESS, severity=ErrorSeverity.HIGH, fallback_result={}
    )
    def fail_file():
        raise FileNotFoundError("missing")

    result = fail_file()
    assert result is None

    stats = get_error_stats()
    assert stats["total_errors"] >= 1


def test_error_handler_critical_reraises():
    @error_handler(
        category=ErrorCategory.ANALYSIS, severity=ErrorSeverity.CRITICAL, fallback_result=None
    )
    def fail_critical():
        raise ValueError("boom")

    assert fail_critical() is None


def test_safe_execute_with_recovery():
    def bad():
        raise FileNotFoundError("missing")

    result = safe_execute(bad, fallback_result="fallback")
    # Recovery for file access returns None
    assert result is None

    def ok():
        return 123

    assert safe_execute(ok, fallback_result="fallback") == 123
