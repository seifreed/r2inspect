#!/usr/bin/env python3
"""Shared models and enums for the error classification subsystem."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
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


@dataclass(eq=False)
class ErrorInfo:
    """Immutable-ish record describing one classified error."""

    exception: Exception
    severity: ErrorSeverity
    category: ErrorCategory
    context: dict[str, Any] = field(default_factory=dict)
    recoverable: bool = True
    suggested_action: str | None = None
    timestamp: float = field(default_factory=time.time)
    thread_id: int = field(default_factory=threading.get_ident)

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
