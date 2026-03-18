"""Pure domain logic for import collection.

This module contains pure functions for import data normalization
with no infrastructure dependencies (stdlib only).
"""

from __future__ import annotations

from typing import Any


def safe_len(value: Any) -> int:
    """Safely get length of any value, returning 0 on error."""
    try:
        return len(value)
    except (TypeError, AttributeError):
        return 0


def normalize_import_entries(imports: Any) -> list[dict[str, Any]]:
    """Normalize import entries to a list of dicts."""
    if not isinstance(imports, list):
        return []
    return [imp for imp in imports if isinstance(imp, dict)]


__all__ = [
    "safe_len",
    "normalize_import_entries",
]
