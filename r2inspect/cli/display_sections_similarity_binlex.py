#!/usr/bin/env python3
"""Binlex and Binbloom display helpers."""

from __future__ import annotations

from collections.abc import Iterable
import re
from typing import Any, cast

from rich.table import Table

from .display_base import (
    ANALYZED_FUNCTIONS_LABEL,
    HTML_AMP,
    SIMILAR_GROUPS_LABEL,
    STATUS_AVAILABLE,
    STATUS_NOT_AVAILABLE,
    TOTAL_FUNCTIONS_LABEL,
    UNKNOWN_ERROR,
    format_hash_display,
)
from .display_sections_common import Results, _get_console
from .presenter import get_section as _get_section


def _display_binlex(results: Results) -> None:
    binlex_info, present = _get_section(results, "binlex", {})
    if not present:
        return
    table = Table(title="Binlex (N-gram Lexical Analysis)", show_header=True, expand=True)
    table.add_column("Property", style="cyan", width=26, no_wrap=True)
    table.add_column("Value", style="yellow", min_width=40, overflow="fold")

    if binlex_info.get("available"):
        _add_binlex_entries(table, binlex_info)
        table.add_row("Status", STATUS_AVAILABLE)
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if binlex_info.get("error"):
            table.add_row("Error", binlex_info.get("error", UNKNOWN_ERROR))

    _get_console().print(table)
    _get_console().print()


def _add_binlex_entries(table: Table, binlex_info: dict[str, Any]) -> None:
    ngram_sizes = _add_binlex_basic_stats(table, binlex_info)
    _add_binlex_unique_signatures(table, ngram_sizes, binlex_info.get("unique_signatures", {}))
    _add_binlex_similarity_groups(table, ngram_sizes, binlex_info.get("similar_functions", {}))
    _add_binlex_binary_signatures(table, ngram_sizes, binlex_info.get("binary_signature", {}))
    _add_binlex_top_ngrams(table, ngram_sizes, binlex_info.get("top_ngrams", {}))


def _lookup_ngram_value(mapping: dict[Any, Any], n: Any) -> Any | None:
    if n in mapping:
        return mapping[n]
    key = str(n)
    if key in mapping:
        return mapping[key]
    return None


def _add_binlex_basic_stats(table: Table, binlex_info: dict[str, Any]) -> list[Any]:
    total_functions = binlex_info.get("total_functions", 0)
    table.add_row(TOTAL_FUNCTIONS_LABEL, str(total_functions))

    analyzed_functions = binlex_info.get("analyzed_functions", 0)
    table.add_row(ANALYZED_FUNCTIONS_LABEL, str(analyzed_functions))

    ngram_sizes = binlex_info.get("ngram_sizes", [])
    if isinstance(ngram_sizes, list):
        ngram_source = ngram_sizes
    elif isinstance(ngram_sizes, (dict, str, bytes)) or not isinstance(ngram_sizes, Iterable):
        ngram_source = []
    else:
        ngram_source = list(ngram_sizes)
    ngram_sizes = ngram_source
    table.add_row("N-gram Sizes", ", ".join(map(str, ngram_sizes)))
    return ngram_sizes


def _add_binlex_unique_signatures(
    table: Table, ngram_sizes: list[Any], unique_signatures: dict[str, Any]
) -> None:
    for n in ngram_sizes:
        value = _lookup_ngram_value(unique_signatures, n)
        if value is not None:
            table.add_row(f"Unique {n}-gram Signatures", str(value))


def _add_binlex_similarity_groups(
    table: Table, ngram_sizes: list[Any], similar_functions: dict[str, Any]
) -> None:
    for n in ngram_sizes:
        groups = _lookup_ngram_value(similar_functions, n)
        if isinstance(groups, list):
            group_source = groups
        elif isinstance(groups, (dict, str, bytes)) or not isinstance(groups, Iterable):
            continue
        else:
            group_source = list(groups)
        if not group_source:
            continue
        largest_group = group_source[0]
        if not isinstance(largest_group, dict):
            continue
        count = largest_group.get("count")
        if count is None:
            continue
        table.add_row(f"Similar {n}-gram Groups", str(len(group_source)))
        table.add_row(f"Largest {n}-gram Group", f"{count} functions")


def _add_binlex_binary_signatures(
    table: Table, ngram_sizes: list[Any], binary_signature: dict[str, Any]
) -> None:
    for n in ngram_sizes:
        sig = _lookup_ngram_value(binary_signature, n)
        if sig is not None:
            table.add_row(f"Binary {n}-gram Signature", format_hash_display(sig, max_length=64))


def _add_binlex_top_ngrams(
    table: Table, ngram_sizes: list[Any], top_ngrams: dict[str, Any]
) -> None:
    for n in ngram_sizes:
        ngram_entries = _lookup_ngram_value(top_ngrams, n)
        if isinstance(ngram_entries, list):
            entry_source = ngram_entries
        elif isinstance(ngram_entries, (dict, str, bytes)) or not isinstance(ngram_entries, Iterable):
            continue
        else:
            entry_source = list(ngram_entries)
        if entry_source:
            top_3 = entry_source[:3]
            ngram_strs = []
            for item in top_3:
                if not isinstance(item, (list, tuple)) or len(item) < 2:
                    continue
                ngram, count = item[0], item[1]
                clean_ngram = str(ngram).replace("&nbsp;", " ").replace(HTML_AMP, "&").strip()
                if len(clean_ngram) > 50:
                    clean_ngram = clean_ngram[:47] + "..."
                ngram_strs.append(f"• {clean_ngram} ({count})")
            table.add_row(f"Top {n}-grams", "\n".join(ngram_strs))


__all__ = [
    "SIMILAR_GROUPS_LABEL",
    "re",
]
