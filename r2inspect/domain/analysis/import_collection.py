"""Pure domain logic for import collection.

This module contains pure functions for import data normalization
with no infrastructure dependencies (stdlib only).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ...abstractions.coercion_support import coerce_dict_list


def safe_len(value: Any) -> int:
    """Safely get length of any value, returning 0 on error."""
    try:
        return len(value)
    except (TypeError, AttributeError):
        return 0


def normalize_import_entries(imports: Any) -> list[dict[str, Any]]:
    """Normalize import entries to a list of dicts."""
    if isinstance(imports, Iterable) and not isinstance(imports, (dict, str, bytes)):
        try:
            imports = list(imports)
        except TypeError:
            return []
    return coerce_dict_list(imports)


__all__ = [
    "safe_len",
    "normalize_import_entries",
]
