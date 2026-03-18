#!/usr/bin/env python3
"""Display dispatch helpers for top-level CLI rendering."""

from __future__ import annotations

DISPLAY_ORDER = [
    "_display_file_info",
    "_display_pe_info",
    "_display_security",
    "_display_ssdeep",
    "_display_tlsh",
    "_display_telfhash",
    "_display_rich_header",
    "_display_impfuzzy",
    "_display_ccbhash",
    "_display_binlex",
    "_display_binbloom",
    "_display_simhash",
    "_display_bindiff",
    "_display_machoc_functions",
    "_display_indicators",
]


def display_results_sections(results: dict[str, object]) -> None:
    from . import display_sections

    for name in DISPLAY_ORDER:
        getattr(display_sections, name)(results)
