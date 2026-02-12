#!/usr/bin/env python3
"""Display helpers for file and format sections."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.table import Table

from .display_base import create_info_table
from .presenter import get_section as _get_section

Results = dict[str, Any]


def _get_console() -> Console:
    from . import display as display_module

    return display_module.console


def _display_file_info(results: Results) -> None:
    file_info, present = _get_section(results, "file_info", {})
    if not present:
        return
    table = create_info_table("File Information", prop_width=14, value_min_width=60)

    basic_info = {
        "size": file_info.get("size"),
        "path": file_info.get("path"),
        "name": file_info.get("name"),
        "mime_type": file_info.get("mime_type"),
        "file_type": file_info.get("file_type"),
        "md5": file_info.get("md5"),
        "sha1": file_info.get("sha1"),
        "sha256": file_info.get("sha256"),
        "sha512": file_info.get("sha512"),
    }

    enhanced = file_info.get("enhanced_detection", {})
    if enhanced:
        table.add_row("Format", enhanced.get("file_format", "Unknown"))
        table.add_row("Category", enhanced.get("format_category", "Unknown"))
        table.add_row(
            "Architecture",
            f"{enhanced.get('architecture', 'Unknown')} ({enhanced.get('bits', 'Unknown')} bits)",
        )
        table.add_row("Endianness", enhanced.get("endianness", "Unknown"))
        table.add_row("Confidence", f"{enhanced.get('confidence', 0):.2%}")
        table.add_row("Threat Level", file_info.get("threat_level", "Unknown"))

    for key, value in basic_info.items():
        if value is not None:
            display_key = key.replace("_", " ").title()
            if key in ["sha256", "sha512"]:
                value = str(value)
            table.add_row(display_key, str(value))

    _get_console().print(table)
    _get_console().print()


def _display_pe_info(results: Results) -> None:
    pe_info, present = _get_section(results, "pe_info", {})
    if not present:
        return
    table = Table(title="PE Analysis", show_header=True, expand=True)
    table.add_column("Property", style="cyan", width=15, no_wrap=True)
    table.add_column("Value", style="yellow", min_width=30, overflow="fold")

    excluded_keys = {
        "architecture",
        "bits",
        "format",
        "security_features",
        "machine",
        "endian",
    }

    for key, value in pe_info.items():
        if key in excluded_keys:
            continue
        if isinstance(value, list):
            value = ", ".join(map(str, value))
        elif isinstance(value, dict):
            continue
        table.add_row(key.replace("_", " ").title(), str(value))

    _get_console().print(table)
    _get_console().print()


def _display_security(results: Results) -> None:
    security, present = _get_section(results, "security", {})
    if not present:
        return
    table = Table(title="Security Features", show_header=True)
    table.add_column("Feature", style="cyan")
    table.add_column("Status", style="magenta")

    for key, value in security.items():
        status = "[green]✓[/green]" if value else "[red]✗[/red]"
        table.add_row(key.replace("_", " ").title(), status)

    _get_console().print(table)
    _get_console().print()
