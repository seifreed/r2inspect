#!/usr/bin/env python3
"""Hashing display helpers for TLSH and Telfhash."""

from __future__ import annotations

from typing import Any

from rich.table import Table

from .display_base import (
    STATUS_AVAILABLE,
    STATUS_NOT_AVAILABLE,
    STATUS_NOT_AVAILABLE_SIMPLE,
    UNKNOWN_ERROR,
)
from .display_sections_common import Results, _get_console
from .presenter import get_section as _get_section


def display_tlsh(results: Results) -> None:
    tlsh_info, present = _get_section(results, "tlsh", {})
    if not present:
        return
    table = Table(title="TLSH Locality Sensitive Hash", show_header=True, expand=True)
    table.add_column("Property", style="cyan", width=21, no_wrap=True)
    table.add_column("Value", style="yellow", min_width=70, overflow="fold")
    if tlsh_info.get("available"):
        add_tlsh_entries(table, tlsh_info)
        table.add_row("Status", STATUS_AVAILABLE)
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if tlsh_info.get("error"):
            table.add_row("Error", tlsh_info.get("error", UNKNOWN_ERROR))
    _get_console().print(table)
    _get_console().print()


def add_tlsh_entries(table: Table, tlsh_info: dict[str, Any]) -> None:
    binary_tlsh = tlsh_info.get("binary_tlsh")
    table.add_row("Binary TLSH", binary_tlsh if binary_tlsh else STATUS_NOT_AVAILABLE_SIMPLE)
    text_tlsh = tlsh_info.get("text_section_tlsh")
    table.add_row("Text Section TLSH", text_tlsh if text_tlsh else STATUS_NOT_AVAILABLE_SIMPLE)
    stats = tlsh_info.get("stats", {})
    table.add_row("Functions Analyzed", str(stats.get("functions_analyzed", 0)))
    table.add_row("Functions with TLSH", str(stats.get("functions_with_tlsh", 0)))


def display_telfhash(results: Results) -> None:
    telfhash_info, present = _get_section(results, "telfhash", {})
    if not present:
        return
    table = Table(title="Telfhash (ELF Symbol Hash)", show_header=True)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="yellow")
    if telfhash_info.get("available"):
        if telfhash_info.get("is_elf"):
            add_telfhash_entries(table, telfhash_info)
            table.add_row("Status", STATUS_AVAILABLE)
        else:
            table.add_row("Status", "[yellow]⚠ Not ELF File[/yellow]")
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if telfhash_info.get("error"):
            table.add_row("Error", telfhash_info.get("error", UNKNOWN_ERROR))
    _get_console().print(table)
    _get_console().print()


def add_telfhash_entries(table: Table, telfhash_info: dict[str, Any]) -> None:
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
