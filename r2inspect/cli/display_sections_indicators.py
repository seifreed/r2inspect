#!/usr/bin/env python3
"""Indicator display section."""

from __future__ import annotations

from rich.table import Table

from .display_sections_common import Results, _get_console
from .presenter import get_section as _get_section


def _display_indicators(results: Results) -> None:
    indicators, present = _get_section(results, "indicators", [])
    if not present or not indicators:
        return

    table = Table(title="Suspicious Indicators", show_header=True)
    table.add_column("Type", style="red")
    table.add_column("Description", style="yellow")
    table.add_column("Severity", style="magenta")

    for indicator in indicators:
        table.add_row(
            indicator.get("type", "Unknown"),
            indicator.get("description", "N/A"),
            indicator.get("severity", "Unknown"),
        )

    _get_console().print(table)
    _get_console().print()
