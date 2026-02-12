#!/usr/bin/env python3
"""Metadata-oriented display sections."""

from __future__ import annotations

from typing import Any

from rich.table import Table

from .display_base import STATUS_AVAILABLE, STATUS_NOT_AVAILABLE, UNKNOWN_ERROR
from .display_sections_common import Results, _get_console
from .presenter import get_section as _get_section


def _display_rich_header(results: Results) -> None:
    rich_header_info, present = _get_section(results, "rich_header", {})
    if not present:
        return
    table = Table(title="Rich Header (PE Build Environment)", show_header=True)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="yellow")

    if rich_header_info.get("available"):
        if rich_header_info.get("is_pe"):
            _add_rich_header_entries(table, rich_header_info)
            table.add_row("Status", STATUS_AVAILABLE)
        else:
            table.add_row("Status", "[yellow]⚠ Not PE File[/yellow]")
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if rich_header_info.get("error"):
            table.add_row("Error", rich_header_info.get("error", UNKNOWN_ERROR))

    _get_console().print(table)
    _get_console().print()


def _add_rich_header_entries(table: Table, rich_header_info: dict[str, Any]) -> None:
    xor_key = rich_header_info.get("xor_key")
    if xor_key is not None:
        table.add_row("XOR Key", f"0x{xor_key:08X}")

    checksum = rich_header_info.get("checksum")
    if checksum is not None:
        table.add_row("Checksum", f"0x{checksum:08X}")

    richpe_hash = rich_header_info.get("richpe_hash")
    if richpe_hash:
        table.add_row("RichPE Hash", richpe_hash)

    compilers = rich_header_info.get("compilers", [])
    table.add_row("Compiler Entries", str(len(compilers)))

    if compilers:
        compiler_summary = []
        for compiler in compilers[:5]:
            name = compiler.get("compiler_name", "Unknown")
            count = compiler.get("count", 0)
            build = compiler.get("build_number", 0)
            compiler_summary.append(f"{name} (Build {build}): {count}")

        if len(compilers) > 5:
            compiler_summary.append(f"... and {len(compilers) - 5} more")

        table.add_row("Compilers Used", "\n".join(compiler_summary))
