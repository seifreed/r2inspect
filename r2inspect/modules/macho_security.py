#!/usr/bin/env python3
"""Mach-O security feature helpers."""

from __future__ import annotations

from typing import Any

from ..domain.formats.macho_security import (
    has_arc,
    has_stack_canary,
    is_encrypted,
    is_pie,
    is_signed,
)


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
        info = _get_info(adapter)
        features["pie"] = is_pie(info)
        symbols = adapter.get_symbols()
        features["stack_canary"] = has_stack_canary(symbols)
        features["arc"] = has_arc(symbols)
        bin_info = info.get("bin", {}) if isinstance(info, dict) else {}
        features["encrypted"] = is_encrypted(bin_info)
        features["signed"] = is_signed(_get_load_commands_text(adapter))
        features["nx"] = True
    except Exception as exc:
        logger.error("Error checking security features: %s", exc)

    return features


def _get_load_commands_text(adapter: Any) -> str:
    # Mach-O load commands (LC_CODE_SIGNATURE etc.) are not in ihj; they are in
    # the iH load-command dump.
    getter = getattr(adapter, "cmd", None)
    if not callable(getter):
        return ""
    text = getter("iH")
    return text if isinstance(text, str) else ""


def _get_info(adapter: Any) -> dict[str, Any] | None:
    if adapter is None:
        return None
    info = adapter.get_file_info()
    return info if info else None
