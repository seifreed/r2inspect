#!/usr/bin/env python3
"""Pure classification policy for the error handling subsystem."""

from __future__ import annotations

from typing import Any

from .classifier_logic import (
    adjust_classification as _adjust_classification,
    classify_by_inheritance as _classify_by_inheritance,
    is_recoverable as _is_recoverable,
    suggest_action as _suggest_action,
)
from .classifier_models import ErrorCategory, ErrorInfo, ErrorSeverity


class ErrorClassifier:
    """Classify exceptions into categories and severities."""

    EXCEPTION_MAPPING = {
        MemoryError: (ErrorCategory.MEMORY, ErrorSeverity.CRITICAL),
        OSError: (ErrorCategory.FILE_ACCESS, ErrorSeverity.MEDIUM),
        FileNotFoundError: (ErrorCategory.FILE_ACCESS, ErrorSeverity.HIGH),
        PermissionError: (ErrorCategory.FILE_ACCESS, ErrorSeverity.HIGH),
        IsADirectoryError: (ErrorCategory.FILE_ACCESS, ErrorSeverity.MEDIUM),
        ValueError: (ErrorCategory.INPUT_VALIDATION, ErrorSeverity.MEDIUM),
        TypeError: (ErrorCategory.INPUT_VALIDATION, ErrorSeverity.MEDIUM),
        ConnectionError: (ErrorCategory.NETWORK, ErrorSeverity.MEDIUM),
        TimeoutError: (ErrorCategory.NETWORK, ErrorSeverity.MEDIUM),
        ImportError: (ErrorCategory.DEPENDENCY, ErrorSeverity.HIGH),
        ModuleNotFoundError: (ErrorCategory.DEPENDENCY, ErrorSeverity.HIGH),
    }

    @classmethod
    def classify(cls, exception: Exception, context: dict[str, Any] | None = None) -> ErrorInfo:
        """Classify one exception using the static policy table plus context rules."""
        context = context or {}
        category, severity = cls._base_classification(exception)

        category, severity = cls._adjust_classification(exception, category, severity, context)
        recoverable = cls._is_recoverable(exception, severity, context)
        suggested_action = cls._suggest_action(exception, category, severity, context)

        return ErrorInfo(
            exception=exception,
            severity=severity,
            category=category,
            context=context,
            recoverable=recoverable,
            suggested_action=suggested_action,
        )

    @classmethod
    def _base_classification(cls, exception: Exception) -> tuple[ErrorCategory, ErrorSeverity]:
        exc_type = type(exception)
        if exc_type in cls.EXCEPTION_MAPPING:
            return cls.EXCEPTION_MAPPING[exc_type]
        return cls._classify_by_inheritance(exception)

    @classmethod
    def _classify_by_inheritance(cls, exception: Exception) -> tuple[ErrorCategory, ErrorSeverity]:
        return _classify_by_inheritance(
            exception,
            cls.EXCEPTION_MAPPING,
            error_category_unknown=ErrorCategory.UNKNOWN,
            error_severity_low=ErrorSeverity.LOW,
            error_category_r2pipe=ErrorCategory.R2PIPE,
            error_severity_medium=ErrorSeverity.MEDIUM,
        )

    @classmethod
    def _adjust_classification(
        cls,
        exception: Exception,
        category: ErrorCategory,
        severity: ErrorSeverity,
        context: dict[str, Any],
    ) -> tuple[ErrorCategory, ErrorSeverity]:
        return _adjust_classification(
            category,
            severity,
            context,
            error_category_memory=ErrorCategory.MEMORY,
            error_category_r2pipe=ErrorCategory.R2PIPE,
            error_severity_medium=ErrorSeverity.MEDIUM,
            error_severity_high=ErrorSeverity.HIGH,
            error_severity_critical=ErrorSeverity.CRITICAL,
        )

    @classmethod
    def _is_recoverable(
        cls, exception: Exception, severity: ErrorSeverity, context: dict[str, Any]
    ) -> bool:
        return _is_recoverable(
            exception,
            severity,
            context,
            error_severity_critical=ErrorSeverity.CRITICAL,
        )

    @classmethod
    def _suggest_action(
        cls,
        exception: Exception,
        category: ErrorCategory,
        severity: ErrorSeverity,
        context: dict[str, Any],
    ) -> str:
        return _suggest_action(
            exception,
            category,
            severity,
            error_category_memory=ErrorCategory.MEMORY,
            error_category_file_access=ErrorCategory.FILE_ACCESS,
            error_category_r2pipe=ErrorCategory.R2PIPE,
            error_category_dependency=ErrorCategory.DEPENDENCY,
            error_category_input_validation=ErrorCategory.INPUT_VALIDATION,
            error_severity_critical=ErrorSeverity.CRITICAL,
        )


__all__ = ["ErrorClassifier"]
