#!/usr/bin/env python3
"""Search helpers for backend queries."""

from __future__ import annotations

from typing import Any, cast


def _normalize_pattern(pattern: str) -> str:
    return pattern.strip()


def search_text(adapter: Any, _r2: Any, pattern: str) -> str:
    pattern = _normalize_pattern(pattern)
    if adapter is not None and hasattr(adapter, "search_text"):
        return cast(str, adapter.search_text(pattern))
    return ""


def search_hex(adapter: Any, _r2: Any, pattern: str) -> str:
    pattern = _normalize_pattern(pattern)
    if adapter is not None and hasattr(adapter, "search_hex"):
        return cast(str, adapter.search_hex(pattern))
    return ""
