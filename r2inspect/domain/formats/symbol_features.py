#!/usr/bin/env python3
"""Shared symbol-list feature helpers for format security analysis."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def any_symbol_name(symbols: list[dict[str, Any]] | None, predicate: Callable[[str], bool]) -> bool:
    """True when any well-formed symbol's name satisfies ``predicate``."""
    for symbol in symbols or []:
        if not isinstance(symbol, dict):
            continue
        name = symbol.get("name", "")
        if not isinstance(name, str):
            continue
        if predicate(name):
            return True
    return False
