"""Pure domain logic for import collection.

This module contains pure functions for import data normalization
with no infrastructure dependencies (stdlib only).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def safe_len(value: Any) -> int:
    """Safely get length of any value, returning 0 on error."""
    try:
        return len(value)
    except (TypeError, AttributeError):
        return 0


def normalize_import_entries(imports: Any) -> list[dict[str, Any]]:
    """Normalize import entries to a list of dicts."""
    if isinstance(imports, list):
        source = imports
    elif isinstance(imports, (dict, str, bytes)) or not isinstance(imports, Iterable):
        return []
    else:
        source = list(imports)
    return [imp for imp in source if isinstance(imp, dict)]


__all__ = [
    "safe_len",
    "normalize_import_entries",
]
