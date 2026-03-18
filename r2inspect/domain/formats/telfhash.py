#!/usr/bin/env python3
"""Pure domain logic for ELF telfhash symbol filtering.

This module contains pure functions for telfhash symbol processing
with no infrastructure dependencies (stdlib only).
"""

from __future__ import annotations

from typing import Any, cast


def normalize_telfhash_value(value: Any) -> str | None:
    """Normalize a telfhash value to a clean string."""
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned or cleaned == "-":
        return None
    return cleaned


def parse_telfhash_result(telfhash_result: Any) -> tuple[str | None, str | None]:
    """Parse telfhash result from various formats."""
    hash_value = None
    message = None
    if isinstance(telfhash_result, list) and len(telfhash_result) > 0:
        result_dict = telfhash_result[0]
        hash_value = normalize_telfhash_value(result_dict.get("telfhash"))
        message = cast(str | None, result_dict.get("msg"))
    elif isinstance(telfhash_result, dict):
        hash_value = normalize_telfhash_value(telfhash_result.get("telfhash"))
        message = cast(str | None, telfhash_result.get("msg"))
    else:
        hash_value = normalize_telfhash_value(telfhash_result)
    return hash_value, message


def should_skip_symbol(symbol_name: str) -> bool:
    """Check if a symbol should be skipped for telfhash."""
    if len(symbol_name) < 2:
        return True
    skip_patterns = ["__", "_GLOBAL_", "_DYNAMIC", ".L", "_edata", "_end", "_start"]
    return any(symbol_name.startswith(pattern) for pattern in skip_patterns)


def filter_symbols_for_telfhash(symbols: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter symbols for telfhash processing."""
    filtered: list[dict[str, Any]] = []
    for sym in symbols:
        sym_type = sym.get("type", "").upper()
        sym_bind = sym.get("bind", "").upper()
        sym_name = sym.get("name", "")
        if sym_type not in {"FUNC", "OBJECT"}:
            continue
        if sym_bind == "LOCAL":
            continue
        if not sym_name or sym_name.strip() == "":
            continue
        if should_skip_symbol(sym_name):
            continue
        filtered.append(sym)
    return filtered


def extract_symbol_names(symbols: list[dict[str, Any]]) -> list[str]:
    """Extract sorted symbol names from a list of symbols."""
    names = [sym.get("name", "").strip() for sym in symbols if sym.get("name", "").strip()]
    names.sort()
    return names


__all__ = [
    "normalize_telfhash_value",
    "parse_telfhash_result",
    "should_skip_symbol",
    "filter_symbols_for_telfhash",
    "extract_symbol_names",
]
