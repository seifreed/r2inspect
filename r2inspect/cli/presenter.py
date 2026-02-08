#!/usr/bin/env python3
"""Presentation helpers for CLI display output."""

from __future__ import annotations

from typing import Any


def normalize_display_results(results: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize display results and preserve original presence info."""
    normalized = dict(results or {})
    normalized.setdefault("__present__", set(normalized.keys()))
    return normalized


def get_section(results: dict[str, Any], key: str, default: Any) -> tuple[Any, bool]:
    """Return (section, present) for display rendering."""
    present = results.get("__present__")
    if isinstance(present, set):
        if key not in present:
            return default, False
    elif key not in results:
        return default, False
    return results.get(key, default), True
