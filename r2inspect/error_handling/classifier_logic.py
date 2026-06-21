#!/usr/bin/env python3
"""Internal classification and recovery helpers."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .classifier_models import ErrorCategory, ErrorSeverity


def classify_by_inheritance(
    exception: Exception,
    exception_mapping: dict[type[Exception], tuple[ErrorCategory, ErrorSeverity]],
) -> tuple[ErrorCategory, ErrorSeverity]:
    # Scan most-derived types first (longer MRO = more specific), so e.g. a
    # FileNotFoundError subclass is classified by FileNotFoundError (HIGH) rather
    # than by its OSError base (MEDIUM), which dict-insertion order lists first.
    ordered = sorted(exception_mapping.items(), key=lambda item: len(item[0].__mro__), reverse=True)
    for exc_type, (category, severity) in ordered:
        if isinstance(exception, exc_type):
            return category, severity
    if "r2pipe" in str(type(exception)).lower() or "r2pipe" in str(exception).lower():
        return ErrorCategory.R2PIPE, ErrorSeverity.MEDIUM
    return ErrorCategory.UNKNOWN, ErrorSeverity.LOW


def adjust_classification(
    category: ErrorCategory,
    severity: ErrorSeverity,
    context: dict[str, Any],
) -> tuple[ErrorCategory, ErrorSeverity]:
    if (
        context.get("analysis_type") in ["pe_analysis", "elf_analysis", "macho_analysis"]
        and severity == ErrorSeverity.MEDIUM
    ):
        severity = ErrorSeverity.HIGH
    # NOTE: batch_mode no longer downgrades severity — HIGH errors in batch
    # must remain HIGH to avoid silent data corruption.
    if category == ErrorCategory.MEMORY and context.get("file_size_mb", 0) > 100:
        severity = ErrorSeverity.HIGH
    if category == ErrorCategory.R2PIPE and context.get("phase") == "initialization":
        severity = ErrorSeverity.CRITICAL
    return category, severity


def is_recoverable(
    exception: Exception,
    severity: ErrorSeverity,
    context: dict[str, Any],
) -> bool:
    if severity == ErrorSeverity.CRITICAL:
        return False
    if isinstance(exception, MemoryError):
        return bool(context.get("memory_cleanup_available", True))
    if isinstance(exception, FileNotFoundError | PermissionError):
        return bool(context.get("component_optional", True))
    return True


def suggest_action(
    exception: Exception,
    category: ErrorCategory,
    severity: ErrorSeverity,
) -> str:
    if category == ErrorCategory.MEMORY:
        if severity == ErrorSeverity.CRITICAL:
            return "Restart analysis with smaller file or increase memory limits"
        return "Trigger garbage collection and continue with reduced analysis"
    if category == ErrorCategory.FILE_ACCESS:
        if isinstance(exception, FileNotFoundError):
            return "Skip this component and continue analysis"
        if isinstance(exception, PermissionError):
            return "Check file permissions or run with appropriate privileges"
    if category == ErrorCategory.R2PIPE:
        return "Retry command with fallback options or skip this analysis"
    if category == ErrorCategory.DEPENDENCY:
        return "Install missing dependency or disable related functionality"
    if category == ErrorCategory.INPUT_VALIDATION:
        return "Validate input and retry with corrected parameters"
    return "Log error and continue with remaining analysis"


def error_stats(
    error_counts: dict[Any, int], recent_errors: list[Any], strategy_count: int
) -> dict[str, Any]:
    severity_counts: dict[str, int] = defaultdict(int)
    for error in recent_errors:
        severity_counts[error.severity.value] += 1
    return {
        "total_errors": sum(error_counts.values()),
        "recent_errors": len(recent_errors),
        "errors_by_category": dict(error_counts),
        "errors_by_severity": dict(severity_counts),
        "recovery_strategies_available": strategy_count,
    }
