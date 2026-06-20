"""Small collection coercion helpers shared across layers."""

from __future__ import annotations

from collections.abc import Iterable
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


def is_byte_list(values: Iterable[Any]) -> bool:
    """True when every element is an int within the 0-255 byte range."""
    return all(isinstance(value, int) and 0 <= value <= 0xFF for value in values)


def coerce_number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def coerce_int(value: Any, default: int = 0) -> int:
    try:
        if isinstance(value, str):
            # base 0 auto-detects 0x/0b prefixes but rejects zero-padded decimals
            # ("010", "08"); fall back to base 10 so those keep their real value.
            try:
                return int(value, 0)
            except ValueError:
                return int(value, 10)
        return int(value if value is not None else default)
    except (TypeError, ValueError):
        return default


def coerce_positive_int(value: Any, default: int = 0) -> int:
    result = coerce_int(value, default)
    return result if result > 0 else 0


def coerce_int_or_none(value: Any) -> int | None:
    try:
        if isinstance(value, str):
            return int(value, 0)
        return int(value if value is not None else 0)
    except (TypeError, ValueError):
        return None


def coerce_text(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) else default


def coerce_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def coerce_number_or_none(value: Any) -> float | None:
    try:
        if isinstance(value, str) and not value.strip():
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def get_dict_bucket(mapping: dict[str, Any], key: str) -> dict[str, Any]:
    value = mapping.get(key)
    return value if isinstance(value, dict) else {}


def get_list_bucket(mapping: dict[str, Any], key: str) -> list[Any]:
    value = mapping.get(key)
    if isinstance(value, list):
        return value
    if isinstance(value, (dict, str, bytes)) or not isinstance(value, Iterable):
        return []
    return list(value)


def ensure_dict_bucket(mapping: dict[str, Any], key: str) -> dict[str, Any]:
    value = mapping.get(key)
    if isinstance(value, dict):
        return value
    value = {}
    mapping[key] = value
    return value


def ensure_list_bucket(mapping: dict[str, Any], key: str) -> list[Any]:
    value = mapping.get(key)
    if isinstance(value, list):
        return value
    value = []
    mapping[key] = value
    return value
