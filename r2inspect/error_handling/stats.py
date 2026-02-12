#!/usr/bin/env python3
"""Unified accessors for error and retry statistics."""

from __future__ import annotations

from typing import Any

from ..utils.error_handler import get_error_stats, reset_error_stats
from ..utils.retry_manager import get_retry_stats
from .unified_handler import get_circuit_breaker_stats

__all__ = [
    "get_circuit_breaker_stats",
    "get_error_stats",
    "get_retry_stats",
    "reset_error_stats",
]


def get_error_stats_snapshot() -> dict[str, Any]:
    """Return a consolidated snapshot of available error statistics."""
    return {
        "error_stats": get_error_stats(),
        "retry_stats": get_retry_stats(),
        "circuit_breaker_stats": get_circuit_breaker_stats(),
    }
