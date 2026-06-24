#!/usr/bin/env python3
"""BinDiff display support helpers."""

from __future__ import annotations

from typing import Any

from rich.table import Table

from ..abstractions.coercion_support import coerce_int, coerce_list


def _add_bindiff_entries(table: Table, bindiff_info: dict[str, Any]) -> None:
    filename = bindiff_info.get("filename", "Unknown")
    if not isinstance(filename, str) or not filename:
        filename = "Unknown"
    table.add_row("Filename", filename)

    _add_bindiff_structural(table, bindiff_info.get("structural_features", {}))
    _add_bindiff_functions(table, bindiff_info.get("function_features", {}))
    _add_bindiff_strings(table, bindiff_info.get("string_features", {}))
    _add_bindiff_signatures(table, bindiff_info.get("signatures", {}))


def _add_bindiff_structural(table: Table, structural: dict[str, Any]) -> None:
    if not isinstance(structural, dict) or not structural:
        return
    file_type = structural.get("file_type", "Unknown")
    if not isinstance(file_type, str) or not file_type:
        file_type = "Unknown"
    table.add_row("File Type", file_type)
    table.add_row("File Size", f"{coerce_int(structural.get('file_size', 0)):,} bytes")
    table.add_row("Sections", str(structural.get("section_count", 0)))
    names_row = _section_names_row(structural.get("section_names"))
    if names_row is not None:
        table.add_row("Section Names", names_row)
    table.add_row("Imports", str(structural.get("import_count", 0)))
    table.add_row("Exports", str(structural.get("export_count", 0)))


def _section_names_row(section_names: Any) -> str | None:
    section_source = coerce_list(section_names)
    if not section_source:
        return None
    names = [str(name) for name in section_source]
    if len(names) <= 7:
        return ", ".join(names)
    displayed = names[:5]
    remaining = len(names) - 5
    return f"{', '.join(displayed)}\n... and {remaining} more"


def _add_bindiff_functions(table: Table, function_features: dict[str, Any]) -> None:
    if not isinstance(function_features, dict) or not function_features:
        return
    table.add_row("Functions", str(function_features.get("function_count", 0)))
    if function_features.get("cfg_features"):
        cfg_count = len(function_features["cfg_features"])
        table.add_row("CFG Analysis", f"{cfg_count} functions analyzed")


def _add_bindiff_strings(table: Table, string_features: dict[str, Any]) -> None:
    if not isinstance(string_features, dict) or not string_features:
        return
    table.add_row("Strings", str(string_features.get("total_strings", 0)))
    categorized_strings = string_features.get("categorized_strings")
    if isinstance(categorized_strings, dict) and categorized_strings:
        categories = [str(category) for category in list(categorized_strings.keys())[:3]]
        table.add_row("String Types", ", ".join(categories))


def _add_bindiff_signatures(table: Table, signatures: dict[str, Any]) -> None:
    if not signatures:
        return
    if not isinstance(signatures, dict):
        return
    for key, value in signatures.items():
        if value:
            label = str(key) if key is not None else "unknown"
            table.add_row(f"{label.title()} Signature", str(value))
