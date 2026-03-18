#!/usr/bin/env python3
"""Internal classification and recovery helpers."""

from __future__ import annotations

from collections import defaultdict
from typing import Any


def classify_by_inheritance(
    exception: Exception,
    exception_mapping: dict[type[Exception], tuple[Any, Any]],
    *,
    error_category_unknown: Any,
    error_severity_low: Any,
    error_category_r2pipe: Any,
    error_severity_medium: Any,
) -> tuple[Any, Any]:
    for exc_type, (category, severity) in exception_mapping.items():
        if isinstance(exception, exc_type):
            return category, severity
    if "r2pipe" in str(type(exception)).lower() or "r2pipe" in str(exception).lower():
        return error_category_r2pipe, error_severity_medium
    return error_category_unknown, error_severity_low


def adjust_classification(
    category: Any,
    severity: Any,
    context: dict[str, Any],
    *,
    error_category_memory: Any,
    error_category_r2pipe: Any,
    error_severity_medium: Any,
    error_severity_high: Any,
    error_severity_critical: Any,
) -> tuple[Any, Any]:
    if context.get("analysis_type") in ["pe_analysis", "elf_analysis", "macho_analysis"]:
        if severity == error_severity_medium:
            severity = error_severity_high
    # NOTE: batch_mode no longer downgrades severity — HIGH errors in batch
    # must remain HIGH to avoid silent data corruption.
    if category == error_category_memory and context.get("file_size_mb", 0) > 100:
        severity = error_severity_high
    if category == error_category_r2pipe and context.get("phase") == "initialization":
        severity = error_severity_critical
    return category, severity


def is_recoverable(
    exception: Exception,
    severity: Any,
    context: dict[str, Any],
    *,
    error_severity_critical: Any,
) -> bool:
    if severity == error_severity_critical:
        return False
    if isinstance(exception, MemoryError):
        return bool(context.get("memory_cleanup_available", True))
    if isinstance(exception, FileNotFoundError | PermissionError):
        return bool(context.get("component_optional", True))
    return True


def suggest_action(
    exception: Exception,
    category: Any,
    severity: Any,
    *,
    error_category_memory: Any,
    error_category_file_access: Any,
    error_category_r2pipe: Any,
    error_category_dependency: Any,
    error_category_input_validation: Any,
    error_severity_critical: Any,
) -> str:
    if category == error_category_memory:
        if severity == error_severity_critical:
            return "Restart analysis with smaller file or increase memory limits"
        return "Trigger garbage collection and continue with reduced analysis"
    if category == error_category_file_access:
        if isinstance(exception, FileNotFoundError):
            return "Skip this component and continue analysis"
        if isinstance(exception, PermissionError):
            return "Check file permissions or run with appropriate privileges"
    if category == error_category_r2pipe:
        return "Retry command with fallback options or skip this analysis"
    if category == error_category_dependency:
        return "Install missing dependency or disable related functionality"
    if category == error_category_input_validation:
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
