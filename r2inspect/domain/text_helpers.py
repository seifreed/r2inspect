"""Small text helpers shared by domain models and services."""

from __future__ import annotations

from typing import Any, TypeGuard


def has_text(value: Any) -> TypeGuard[str]:
    return isinstance(value, str) and bool(value.strip())
