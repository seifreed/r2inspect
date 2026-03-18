#!/usr/bin/env python3
"""Misc similarity display helpers."""

from __future__ import annotations

from rich.table import Table

from .display_base import (
    STATUS_AVAILABLE,
    STATUS_NOT_AVAILABLE,
    TOTAL_FUNCTIONS_LABEL,
    UNKNOWN_ERROR,
)
from .display_sections_common import Results, _get_console
from .display_sections_helpers import (
    _add_bindiff_entries,
    _add_simhash_feature_stats,
    _add_simhash_function_analysis,
    _add_simhash_hashes,
    _add_simhash_top_features,
)
from .presenter import get_section as _get_section


def _display_simhash(results: Results) -> None:
    simhash_info, present = _get_section(results, "simhash", {})
    if not present:
        return
    table = Table(title="SimHash (Similarity Hashing)", show_header=True, width=120)
    table.add_column("Property", style="cyan", width=25)
    table.add_column("Value", style="yellow", width=90, overflow="fold")

    if simhash_info.get("available"):
        _add_simhash_feature_stats(table, feature_stats := simhash_info.get("feature_stats", {}))
        _add_simhash_hashes(table, simhash_info)
        _add_simhash_function_analysis(table, simhash_info)
        _add_simhash_top_features(table, feature_stats)
        table.add_row("Status", STATUS_AVAILABLE)
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if simhash_info.get("error"):
            table.add_row("Error", simhash_info.get("error", UNKNOWN_ERROR))
        elif not simhash_info.get("library_available", True):
            table.add_row("Error", "simhash library not installed")
            table.add_row("Install Command", "pip install simhash")

    _get_console().print(table)
    _get_console().print()


def _display_bindiff(results: Results) -> None:
    bindiff_info, present = _get_section(results, "bindiff", {})
    if not present:
        return
    table = Table(title="BinDiff (Binary Comparison Features)", show_header=True)
    table.add_column("Property", style="cyan", width=25)
    table.add_column("Value", style="yellow", no_wrap=False)

    if bindiff_info.get("comparison_ready"):
        _add_bindiff_entries(table, bindiff_info)
        table.add_row("Status", "[green]✓ Comparison Ready[/green]")
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if bindiff_info.get("error"):
            table.add_row("Error", bindiff_info.get("error", UNKNOWN_ERROR))

    _get_console().print(table)
    _get_console().print()


def _display_machoc_functions(results: Results) -> None:
    functions_info, present = _get_section(results, "functions", {})
    if not present:
        return
    table = Table(title="Function Analysis (MACHOC)", show_header=True)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="yellow")

    table.add_row(TOTAL_FUNCTIONS_LABEL, str(functions_info.get("total_functions", 0)))

    machoc_hashes = functions_info.get("machoc_hashes", {})
    unique_hashes = len(set(machoc_hashes.values())) if machoc_hashes else 0
    table.add_row("Unique MACHOC Hashes", str(unique_hashes))

    if machoc_hashes:
        hash_counts: dict[str, int] = {}
        for _, machoc_hash in machoc_hashes.items():
            hash_counts[machoc_hash] = hash_counts.get(machoc_hash, 0) + 1
        duplicates = sum(count - 1 for count in hash_counts.values() if count > 1)
        table.add_row("Duplicate Functions", str(duplicates))

    _get_console().print(table)
    _get_console().print()
