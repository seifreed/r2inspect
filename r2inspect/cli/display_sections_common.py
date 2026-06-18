#!/usr/bin/env python3
"""Shared helpers for display section renderers."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.table import Table

Results = dict[str, Any]


def _get_console() -> Console:
    from .display_base import _get_console as _base_get_console

    return _base_get_console()


def add_group_functions_row(table: Table, group: dict[str, Any], index: int) -> None:
    """Render up to five of a similarity group's functions as a table row."""
    functions = group.get("functions")
    if not functions:
        return
    func_display = []
    for func in functions[:5]:
        func_name = str(func)
        if len(func_name) > 30:
            func_name = func_name[:27] + "..."
        func_display.append(f"• {func_name}")
    if len(functions) > 5:
        func_display.append(f"• ... and {len(functions) - 5} more")
    table.add_row(f"Group {index} Functions", "\n".join(func_display))
