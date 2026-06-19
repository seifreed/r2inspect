"""Small collection coercion helpers shared across layers."""

from __future__ import annotations

from typing import Any


def coerce_dict_list(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        return [raw]
    return coerce_dict_iterable(raw)


def coerce_list(raw: Any) -> list[Any]:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, (dict, str, bytes)) or raw is None:
        return []
    try:
        return list(raw)
    except TypeError:
        return []


def coerce_dict_iterable(raw: Any) -> list[dict[str, Any]]:
    return [item for item in coerce_list(raw) if isinstance(item, dict)]


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
