#!/usr/bin/env python3
"""Shared models and enums for the error classification subsystem."""

from __future__ import annotations

import threading
import time
from enum import Enum
from typing import Any


class ErrorSeverity(Enum):
    """Severity buckets used by recovery and reporting."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """High-level categories used by classification and recovery."""

    INPUT_VALIDATION = "input_validation"
    FILE_ACCESS = "file_access"
    MEMORY = "memory"
    R2PIPE = "r2pipe"
    ANALYSIS = "analysis"
    NETWORK = "network"
    DEPENDENCY = "dependency"
    CONFIGURATION = "configuration"
    UNKNOWN = "unknown"


class ErrorInfo:
    """Immutable-ish record describing one classified error."""

    def __init__(
        self,
        exception: Exception,
        severity: ErrorSeverity,
        category: ErrorCategory,
        context: dict[str, Any] | None = None,
        recoverable: bool = True,
        suggested_action: str | None = None,
    ):
        self.exception = exception
        self.severity = severity
        self.category = category
        self.context = context or {}
        self.recoverable = recoverable
        self.suggested_action = suggested_action
        self.timestamp = time.time()
        self.thread_id = threading.get_ident()

    def to_dict(self) -> dict[str, Any]:
        """Return a serialization-friendly representation."""
        return {
            "exception_type": type(self.exception).__name__,
            "exception_message": str(self.exception),
            "severity": self.severity.value,
            "category": self.category.value,
            "context": self.context,
            "recoverable": self.recoverable,
            "suggested_action": self.suggested_action,
            "timestamp": self.timestamp,
            "thread_id": self.thread_id,
        }


__all__ = ["ErrorCategory", "ErrorInfo", "ErrorSeverity"]
