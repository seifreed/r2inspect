#!/usr/bin/env python3
"""Shared helpers for assembling analyzer result dictionaries."""

from __future__ import annotations

from typing import Any


def init_result(
    analyzer_name: str | None = None,
    additional_fields: dict[str, Any] | None = None,
    *,
    include_execution_time: bool = True,
) -> dict[str, Any]:
    """Create a standardized result dictionary with optional analyzer metadata."""
    result: dict[str, Any] = {
        "available": False,
        "error": None,
    }
    if include_execution_time:
        result["execution_time"] = 0.0
    if analyzer_name:
        result["analyzer"] = analyzer_name
    if additional_fields:
        result.update(additional_fields)
    return result


def mark_unavailable(
    result: dict[str, Any],
    error: str,
    *,
    library_available: bool | None = None,
) -> dict[str, Any]:
    """Mark a result as unavailable with an error message."""
    result["available"] = False
    if library_available is not None:
        result["library_available"] = library_available
    result["error"] = error
    return result
