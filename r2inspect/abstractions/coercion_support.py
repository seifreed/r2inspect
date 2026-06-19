"""Small collection coercion helpers shared across layers."""

from __future__ import annotations

from typing import Any


def coerce_dict_list(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, (str, bytes, bytearray)) or raw is None:
        return []
    try:
        return [item for item in list(raw) if isinstance(item, dict)]
    except TypeError:
        return []


def coerce_number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def coerce_int(value: Any, default: int = 0) -> int:
    try:
        if isinstance(value, str):
            return int(value, 0)
        return int(value if value is not None else default)
    except (TypeError, ValueError):
        return default
