#!/usr/bin/env python3
"""Search helpers for backend queries."""

from __future__ import annotations

from typing import Any


def _normalize_pattern(pattern: str) -> str:
    return pattern.strip()


def search_text(adapter: Any, pattern: str) -> str:
    pattern = _normalize_pattern(pattern)
    if not pattern:
        return ""
    if adapter is not None and hasattr(adapter, "search_text"):
        result = adapter.search_text(pattern)
        return result if isinstance(result, str) else ""
    return ""


def search_hex(adapter: Any, pattern: str) -> str:
    pattern = _normalize_pattern(pattern)
    if not pattern:
        return ""
    if adapter is not None and hasattr(adapter, "search_hex"):
        result = adapter.search_hex(pattern)
        return result if isinstance(result, str) else ""
    return ""
