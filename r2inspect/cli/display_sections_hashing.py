#!/usr/bin/env python3
"""Hashing-related display sections."""

from __future__ import annotations

import re
from typing import Any, cast

from rich.table import Table

from .display_base import (
    ANALYZED_FUNCTIONS_LABEL,
    HTML_AMP,
    SIMILAR_GROUPS_LABEL,
    STATUS_AVAILABLE,
    STATUS_NOT_AVAILABLE,
    STATUS_NOT_AVAILABLE_SIMPLE,
    TOTAL_FUNCTIONS_LABEL,
    UNKNOWN_ERROR,
    format_hash_display,
)
from .display_sections_common import Results, _get_console
from .presenter import get_section as _get_section


def _display_ssdeep(results: Results) -> None:
    ssdeep_info, present = _get_section(results, "ssdeep", {})
    if not present:
        return
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


def _display_tlsh(results: Results) -> None:
    tlsh_info, present = _get_section(results, "tlsh", {})
    if not present:
        return
    table = Table(title="TLSH Locality Sensitive Hash", show_header=True, expand=True)
    table.add_column("Property", style="cyan", width=21, no_wrap=True)
    table.add_column("Value", style="yellow", min_width=70, overflow="fold")

    if tlsh_info.get("available"):
        _add_tlsh_entries(table, tlsh_info)
        table.add_row("Status", STATUS_AVAILABLE)
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if tlsh_info.get("error"):
            table.add_row("Error", tlsh_info.get("error", UNKNOWN_ERROR))

    _get_console().print(table)
    _get_console().print()


def _add_tlsh_entries(table: Table, tlsh_info: dict[str, Any]) -> None:
    binary_tlsh = tlsh_info.get("binary_tlsh")
    table.add_row("Binary TLSH", binary_tlsh if binary_tlsh else STATUS_NOT_AVAILABLE_SIMPLE)

    text_tlsh = tlsh_info.get("text_section_tlsh")
    table.add_row("Text Section TLSH", text_tlsh if text_tlsh else STATUS_NOT_AVAILABLE_SIMPLE)

    stats = tlsh_info.get("stats", {})
    table.add_row("Functions Analyzed", str(stats.get("functions_analyzed", 0)))
    table.add_row("Functions with TLSH", str(stats.get("functions_with_tlsh", 0)))


def _display_telfhash(results: Results) -> None:
    telfhash_info, present = _get_section(results, "telfhash", {})
    if not present:
        return
    table = Table(title="Telfhash (ELF Symbol Hash)", show_header=True)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="yellow")

    if telfhash_info.get("available"):
        if telfhash_info.get("is_elf"):
            _add_telfhash_entries(table, telfhash_info)
            table.add_row("Status", STATUS_AVAILABLE)
        else:
            table.add_row("Status", "[yellow]⚠ Not ELF File[/yellow]")
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if telfhash_info.get("error"):
            table.add_row("Error", telfhash_info.get("error", UNKNOWN_ERROR))

    _get_console().print(table)
    _get_console().print()


def _add_telfhash_entries(table: Table, telfhash_info: dict[str, Any]) -> None:
    telfhash_value = telfhash_info.get("telfhash")
    table.add_row("Telfhash", telfhash_value if telfhash_value else STATUS_NOT_AVAILABLE_SIMPLE)
    table.add_row("Total Symbols", str(telfhash_info.get("symbol_count", 0)))
    table.add_row("Filtered Symbols", str(telfhash_info.get("filtered_symbols", 0)))

    symbols_used = telfhash_info.get("symbols_used", [])
    if symbols_used:
        symbols_preview = ", ".join(symbols_used[:5])
        if len(symbols_used) > 5:
            symbols_preview += f" (+ {len(symbols_used) - 5} more)"
        table.add_row("Symbols Used", symbols_preview)


def _display_impfuzzy(results: Results) -> None:
    impfuzzy_info, present = _get_section(results, "impfuzzy", {})
    if not present:
        return
    table = Table(title="Impfuzzy (PE Import Fuzzy Hash)", show_header=True, expand=True)
    table.add_column("Property", style="cyan", width=16, no_wrap=True)
    table.add_column("Value", style="yellow", min_width=80, overflow="fold")

    if impfuzzy_info.get("available"):
        _add_impfuzzy_entries(table, impfuzzy_info)
        table.add_row("Status", STATUS_AVAILABLE)
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if impfuzzy_info.get("error"):
            table.add_row("Error", impfuzzy_info.get("error", UNKNOWN_ERROR))
        if not impfuzzy_info.get("library_available"):
            table.add_row("Note", "pyimpfuzzy library not installed")

    _get_console().print(table)
    _get_console().print()


def _add_impfuzzy_entries(table: Table, impfuzzy_info: dict[str, Any]) -> None:
    impfuzzy_hash = impfuzzy_info.get("impfuzzy_hash")
    if impfuzzy_hash:
        table.add_row("Impfuzzy Hash", impfuzzy_hash)

    import_count = impfuzzy_info.get("import_count", 0)
    table.add_row("Total Imports", str(import_count))

    dll_count = impfuzzy_info.get("dll_count", 0)
    table.add_row("DLL Count", str(dll_count))

    imports_processed = impfuzzy_info.get("imports_processed", [])
    if imports_processed:
        sample_imports = imports_processed[:10]
        if len(imports_processed) > 10:
            sample_imports.append(f"... and {len(imports_processed) - 10} more")
        table.add_row("Sample Imports", "\n".join(sample_imports))


def _display_ccbhash(results: Results) -> None:
    ccbhash_info, present = _get_section(results, "ccbhash", {})
    if not present:
        return
    table = Table(title="CCBHash (Control Flow Graph Hash)", show_header=True, expand=True)
    table.add_column("Property", style="cyan", width=25, no_wrap=True)
    table.add_column("Value", style="yellow", min_width=50, overflow="fold")

    if ccbhash_info.get("available"):
        _add_ccbhash_entries(table, ccbhash_info)
        table.add_row("Status", STATUS_AVAILABLE)
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if ccbhash_info.get("error"):
            table.add_row("Error", ccbhash_info.get("error", UNKNOWN_ERROR))

    _get_console().print(table)
    _get_console().print()


def _add_ccbhash_entries(table: Table, ccbhash_info: dict[str, Any]) -> None:
    binary_hash = ccbhash_info.get("binary_ccbhash")
    if binary_hash:
        table.add_row("Binary CCBHash", format_hash_display(binary_hash, max_length=64))

    total_functions = ccbhash_info.get("total_functions", 0)
    table.add_row(TOTAL_FUNCTIONS_LABEL, str(total_functions))

    analyzed_functions = ccbhash_info.get("analyzed_functions", 0)
    table.add_row(ANALYZED_FUNCTIONS_LABEL, str(analyzed_functions))

    unique_hashes = ccbhash_info.get("unique_hashes", 0)
    table.add_row("Unique CCBHashes", str(unique_hashes))

    similar_functions = cast(list[dict[str, Any]], ccbhash_info.get("similar_functions", []))
    if not similar_functions:
        return

    table.add_row(SIMILAR_GROUPS_LABEL, str(len(similar_functions)))
    largest_group = similar_functions[0] if similar_functions else None
    if not largest_group:
        return

    table.add_row("Largest Similar Group", f"{largest_group['count']} functions")
    sample_funcs = largest_group["functions"][:3].copy()
    clean_sample_funcs = [
        re.sub(r"&nbsp;?", " ", func).replace(HTML_AMP, "&") for func in sample_funcs
    ]
    if len(largest_group["functions"]) > 3:
        clean_sample_funcs.append(f"... and {len(largest_group['functions']) - 3} more")
    table.add_row("Sample Functions", ", ".join(clean_sample_funcs))
