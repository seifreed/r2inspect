#!/usr/bin/env python3
"""Hashing display helpers for SSDeep, Impfuzzy, and CCBHash."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any, cast

from rich.table import Table

from .display_base import (
    ANALYZED_FUNCTIONS_LABEL,
    HTML_AMP,
    SIMILAR_GROUPS_LABEL,
    STATUS_AVAILABLE,
    STATUS_NOT_AVAILABLE,
    TOTAL_FUNCTIONS_LABEL,
    UNKNOWN_ERROR,
    format_hash_display,
)
from .display_sections_common import Results, _get_console
from .presenter import get_section as _get_section


def display_ssdeep(results: Results) -> None:
    ssdeep_info, present = _get_section(results, "ssdeep", {})
    if not present:
        return
    if not isinstance(ssdeep_info, dict):
        ssdeep_info = {}
    table = Table(title="SSDeep Fuzzy Hash", show_header=True, expand=True)
    table.add_column("Property", style="cyan", width=10, no_wrap=True)
    table.add_column("Value", style="yellow", min_width=50, overflow="fold")
    if ssdeep_info.get("available"):
        table.add_row("Hash", ssdeep_info.get("hash_value", "N/A"))
        table.add_row("Method", ssdeep_info.get("method_used", "Unknown"))
        table.add_row("Status", STATUS_AVAILABLE)
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if ssdeep_info.get("error"):
            table.add_row("Error", ssdeep_info.get("error", UNKNOWN_ERROR))
    _get_console().print(table)
    _get_console().print()


def display_impfuzzy(results: Results) -> None:
    impfuzzy_info, present = _get_section(results, "impfuzzy", {})
    if not present:
        return
    if not isinstance(impfuzzy_info, dict):
        impfuzzy_info = {}
    table = Table(title="Impfuzzy (PE Import Fuzzy Hash)", show_header=True, expand=True)
    table.add_column("Property", style="cyan", width=16, no_wrap=True)
    table.add_column("Value", style="yellow", min_width=80, overflow="fold")
    if impfuzzy_info.get("available"):
        add_impfuzzy_entries(table, impfuzzy_info)
        table.add_row("Status", STATUS_AVAILABLE)
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if impfuzzy_info.get("error"):
            table.add_row("Error", impfuzzy_info.get("error", UNKNOWN_ERROR))
        if not impfuzzy_info.get("library_available"):
            table.add_row("Note", "pyimpfuzzy library not installed")
    _get_console().print(table)
    _get_console().print()


def add_impfuzzy_entries(table: Table, impfuzzy_info: dict[str, Any]) -> None:
    impfuzzy_hash = impfuzzy_info.get("impfuzzy_hash")
    if impfuzzy_hash:
        table.add_row("Impfuzzy Hash", impfuzzy_hash)
    table.add_row("Total Imports", str(impfuzzy_info.get("import_count", 0)))
    table.add_row("DLL Count", str(impfuzzy_info.get("dll_count", 0)))
    imports_processed = impfuzzy_info.get("imports_processed", [])
    if isinstance(imports_processed, list):
        normalized_imports = imports_processed
    elif isinstance(imports_processed, (dict, str, bytes)) or not isinstance(
        imports_processed, Iterable
    ):
        normalized_imports = []
    else:
        normalized_imports = list(imports_processed)
    if normalized_imports:
        sample_imports = list(normalized_imports[:10])
        if len(normalized_imports) > 10:
            sample_imports.append(f"... and {len(normalized_imports) - 10} more")
        table.add_row("Sample Imports", "\n".join(map(str, sample_imports)))


def display_ccbhash(results: Results) -> None:
    ccbhash_info, present = _get_section(results, "ccbhash", {})
    if not present:
        return
    if not isinstance(ccbhash_info, dict):
        ccbhash_info = {}
    table = Table(title="CCBHash (Control Flow Graph Hash)", show_header=True, expand=True)
    table.add_column("Property", style="cyan", width=25, no_wrap=True)
    table.add_column("Value", style="yellow", min_width=50, overflow="fold")
    if ccbhash_info.get("available"):
        add_ccbhash_entries(table, ccbhash_info)
        table.add_row("Status", STATUS_AVAILABLE)
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if ccbhash_info.get("error"):
            table.add_row("Error", ccbhash_info.get("error", UNKNOWN_ERROR))
    _get_console().print(table)
    _get_console().print()


def add_ccbhash_entries(table: Table, ccbhash_info: dict[str, Any]) -> None:
    binary_hash = ccbhash_info.get("binary_ccbhash")
    if binary_hash:
        table.add_row("Binary CCBHash", format_hash_display(binary_hash, max_length=64))
    table.add_row(TOTAL_FUNCTIONS_LABEL, str(ccbhash_info.get("total_functions", 0)))
    table.add_row(ANALYZED_FUNCTIONS_LABEL, str(ccbhash_info.get("analyzed_functions", 0)))
    table.add_row("Unique CCBHashes", str(ccbhash_info.get("unique_hashes", 0)))
    similar_functions = cast(list[dict[str, Any]], ccbhash_info.get("similar_functions", []))
    if not similar_functions:
        return
    table.add_row(SIMILAR_GROUPS_LABEL, str(len(similar_functions)))
    largest_group = similar_functions[0] if similar_functions else None
    if not largest_group:
        return
    if not isinstance(largest_group, dict):
        return
    count = largest_group.get("count")
    if count is None:
        return
    table.add_row("Largest Similar Group", f"{count} functions")
    functions = largest_group.get("functions", [])
    if isinstance(functions, list):
        normalized_functions = functions
    elif isinstance(functions, (dict, str, bytes)) or not isinstance(functions, Iterable):
        return
    else:
        normalized_functions = list(functions)
    sample_funcs = list(normalized_functions[:3])
    clean_sample_funcs = [
        re.sub(r"&nbsp;?", " ", str(func)).replace(HTML_AMP, "&") for func in sample_funcs
    ]
    if len(normalized_functions) > 3:
        clean_sample_funcs.append(f"... and {len(normalized_functions) - 3} more")
    table.add_row("Sample Functions", ", ".join(clean_sample_funcs))
