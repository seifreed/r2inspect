#!/usr/bin/env python3
"""Facade for hashing display renderers."""

from __future__ import annotations

from typing import Any

from .display_sections_hashing_fuzzy_views import (
    add_ccbhash_entries,
    add_impfuzzy_entries,
    display_ccbhash,
    display_impfuzzy,
    display_ssdeep,
)
from .display_sections_hashing_symbol_views import (
    add_telfhash_entries,
    add_tlsh_entries,
    display_telfhash,
    display_tlsh,
)

_get_console: Any = None  # injected at runtime by display_sections_hashing

__all__ = [
    "add_ccbhash_entries",
    "add_impfuzzy_entries",
    "add_telfhash_entries",
    "add_tlsh_entries",
    "display_ccbhash",
    "display_impfuzzy",
    "display_ssdeep",
    "display_telfhash",
    "display_tlsh",
]
