#!/usr/bin/env python3
"""Unified error handling strategy for r2inspect."""

from collections.abc import Callable
from typing import Any

from .classifier_logic import error_stats as _error_stats
from .classifier_models import ErrorCategory, ErrorInfo, ErrorSeverity
from .classifier_policy import ErrorClassifier
from .classifier_recovery import (
    file_access_recovery as _file_access_recovery,
    memory_recovery as _memory_recovery,
    r2pipe_recovery as _r2pipe_recovery,
)
from .classifier_runtime import (
    ErrorRecoveryManager,
    build_error_handler as _build_error_handler,
    _log_error as _runtime_log_error,
    register_default_recovery_strategies as _register_default_recovery_strategies,
    reset_manager_stats as _reset_manager_stats,
    safe_execute_call as _safe_execute_call,
)
from ..infrastructure.logging import get_logger

logger = get_logger(__name__)

# Global error recovery manager — direct instance, no proxy.
global_error_manager = ErrorRecoveryManager(logger, _error_stats)


def reset_global_error_manager() -> None:
    """Reset global error manager state (useful for test isolation)."""
    from .classifier_runtime import reset_manager_stats

    reset_manager_stats(global_error_manager)


def error_handler(
    category: ErrorCategory = ErrorCategory.UNKNOWN,
    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
    context: dict[str, Any] | None = None,
    fallback_result: Any = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator for unified error handling

    Args:
        category: Error category override
        severity: Error severity override
        context: Additional context
        fallback_result: Result to return on unrecoverable error
    """

    return _build_error_handler(
        classifier=ErrorClassifier,
        global_error_manager=global_error_manager,
        error_category_unknown=ErrorCategory.UNKNOWN,
        error_severity_medium=ErrorSeverity.MEDIUM,
        category=category,
        severity=severity,
        context=context,
        fallback_result=fallback_result,
    )


def safe_execute(
    func: Callable[..., Any],
    *args: Any,
    fallback_result: Any = None,
    context: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Any:
    """
    Safely execute a function with error handling

    Args:
        func: Function to execute
        *args: Positional arguments
        fallback_result: Result to return on error
        context: Additional context
        **kwargs: Keyword arguments

    Returns:
        Function result or fallback_result on error
    """
    return _safe_execute_call(
        func,
        *args,
        classifier=ErrorClassifier,
        global_error_manager=global_error_manager,
        fallback_result=fallback_result,
        context=context,
        **kwargs,
    )


def register_recovery_strategies() -> None:
    """Register default recovery strategies"""
    _register_default_recovery_strategies(
        global_error_manager,
        error_category_memory=ErrorCategory.MEMORY,
        error_category_r2pipe=ErrorCategory.R2PIPE,
        error_category_file_access=ErrorCategory.FILE_ACCESS,
        memory_recovery=_memory_recovery,
        r2pipe_recovery=_r2pipe_recovery,
        file_access_recovery=_file_access_recovery,
        logger=logger,
    )


_recovery_strategies_initialized = False


def initialize_error_handling() -> None:
    """Register default recovery strategies (idempotent)."""
    global _recovery_strategies_initialized
    if not _recovery_strategies_initialized:
        register_recovery_strategies()
        _recovery_strategies_initialized = True


def get_error_stats() -> dict[str, Any]:
    """Get global error statistics"""
    return global_error_manager.get_error_stats()


def reset_error_stats() -> None:
    """Reset error statistics"""
    _reset_manager_stats(global_error_manager)
