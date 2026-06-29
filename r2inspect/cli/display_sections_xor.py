#!/usr/bin/env python3
"""XOR string search display section."""

from __future__ import annotations

from rich.table import Table

from .display_sections_common import Results, _get_console
from .presenter import get_section as _get_section


def _display_xor_search(results: Results) -> None:
    xor_search, present = _get_section(results, "xor_search", {})
    if not present or not isinstance(xor_search, dict):
        return

    search_string = xor_search.get("search_string", "")
    matches = xor_search.get("matches", [])
    console = _get_console()
    console.print(f"[bold]XOR Search:[/bold] {search_string}")
    if not matches:
        console.print("  No XOR-encoded matches found")
        console.print()
        return

    table = Table(title="XOR String Matches", show_header=True)
    table.add_column("XOR Key", style="cyan")
    table.add_column("Addresses", style="green")

    for match in matches:
        if not isinstance(match, dict):
            continue
        key = match.get("xor_key")
        key_repr = f"0x{key:02x}" if isinstance(key, int) else str(key)
        addresses = match.get("addresses", [])
        addr_repr = ", ".join(str(a) for a in addresses) if isinstance(addresses, list) else ""
        table.add_row(key_repr, addr_repr)

    console.print(table)
    console.print()
