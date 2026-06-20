"""Small text helpers shared by domain models and services."""

from __future__ import annotations

from typing import Any


def has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
