#!/usr/bin/env python3
"""Mach-O security feature helpers."""

from __future__ import annotations

from typing import Any

from .macho_security_domain import has_arc, has_stack_canary, is_encrypted, is_pie, is_signed


def get_security_features(adapter: Any, logger: Any) -> dict[str, bool]:
    features = {
        "pie": False,
        "nx": False,
        "stack_canary": False,
        "arc": False,
        "encrypted": False,
        "signed": False,
    }

    try:
        features["pie"] = is_pie(_get_info(adapter))
        symbols = adapter.get_symbols()
        features["stack_canary"] = has_stack_canary(symbols)
        features["arc"] = has_arc(symbols)
        headers = _get_headers(adapter)
        features["encrypted"] = is_encrypted(headers)
        features["signed"] = is_signed(headers)
        features["nx"] = True
    except Exception as exc:
        logger.error(f"Error checking security features: {exc}")

    return features


def _get_headers(adapter: Any) -> list[dict[str, Any]]:
    if adapter is None:
        return []
    if hasattr(adapter, "get_headers_json"):
        headers = adapter.get_headers_json()
        if isinstance(headers, dict):
            return [headers]
        if isinstance(headers, list):
            return headers
    return []


def _get_info(adapter: Any) -> dict[str, Any] | None:
    if adapter is None:
        return None
    info = adapter.get_file_info()
    return info if info else None
