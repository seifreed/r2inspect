#!/usr/bin/env python3
"""Compatibility shim for error handling utilities."""

from __future__ import annotations

from ..error_handling.classifier import (
    ErrorCategory,
    ErrorClassifier,
    ErrorInfo,
    ErrorRecoveryManager,
    ErrorSeverity,
    error_handler,
    get_error_stats,
    global_error_manager,
    register_recovery_strategies,
    reset_error_stats,
    safe_execute,
)

__all__ = [
    "ErrorCategory",
    "ErrorClassifier",
    "ErrorInfo",
    "ErrorRecoveryManager",
    "ErrorSeverity",
    "error_handler",
    "get_error_stats",
    "global_error_manager",
    "register_recovery_strategies",
    "reset_error_stats",
    "safe_execute",
]
