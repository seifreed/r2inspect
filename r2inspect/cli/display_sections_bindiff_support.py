#!/usr/bin/env python3
"""BinDiff display support helpers."""

from __future__ import annotations

from typing import Any

from rich.table import Table


def _add_bindiff_entries(table: Table, bindiff_info: dict[str, Any]) -> None:
    table.add_row("Filename", bindiff_info.get("filename", "Unknown"))

    _add_bindiff_structural(table, bindiff_info.get("structural_features", {}))
    _add_bindiff_functions(table, bindiff_info.get("function_features", {}))
    _add_bindiff_strings(table, bindiff_info.get("string_features", {}))
    _add_bindiff_signatures(table, bindiff_info.get("signatures", {}))


def _add_bindiff_structural(table: Table, structural: dict[str, Any]) -> None:
    if not structural:
        return
    table.add_row("File Type", structural.get("file_type", "Unknown"))
    table.add_row("File Size", f"{structural.get('file_size', 0):,} bytes")
    table.add_row("Sections", str(structural.get("section_count", 0)))
    if structural.get("section_names"):
        section_names = structural["section_names"]
        if len(section_names) <= 7:
            table.add_row("Section Names", ", ".join(section_names))
        else:
            displayed = section_names[:5]
            remaining = len(section_names) - 5
            table.add_row("Section Names", f"{', '.join(displayed)}\n... and {remaining} more")
    table.add_row("Imports", str(structural.get("import_count", 0)))
    table.add_row("Exports", str(structural.get("export_count", 0)))


def _add_bindiff_functions(table: Table, function_features: dict[str, Any]) -> None:
    if not function_features:
        return
    table.add_row("Functions", str(function_features.get("function_count", 0)))
    if function_features.get("cfg_features"):
        cfg_count = len(function_features["cfg_features"])
        table.add_row("CFG Analysis", f"{cfg_count} functions analyzed")


def _add_bindiff_strings(table: Table, string_features: dict[str, Any]) -> None:
    if not string_features:
        return
    table.add_row("Strings", str(string_features.get("total_strings", 0)))
    if string_features.get("categorized_strings"):
        categories = list(string_features["categorized_strings"].keys())[:3]
        table.add_row("String Types", ", ".join(categories))


def _add_bindiff_signatures(table: Table, signatures: dict[str, Any]) -> None:
    if not signatures:
        return
    for key, value in signatures.items():
        if value:
            table.add_row(f"{key.title()} Signature", value)
