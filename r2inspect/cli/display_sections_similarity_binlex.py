#!/usr/bin/env python3
"""Binlex and Binbloom display helpers."""

from __future__ import annotations

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


def _add_binlex_basic_stats(table: Table, binlex_info: dict[str, Any]) -> list[Any]:
    total_functions = binlex_info.get("total_functions", 0)
    table.add_row(TOTAL_FUNCTIONS_LABEL, str(total_functions))

    analyzed_functions = binlex_info.get("analyzed_functions", 0)
    table.add_row(ANALYZED_FUNCTIONS_LABEL, str(analyzed_functions))

    ngram_sizes = cast(list[Any], binlex_info.get("ngram_sizes", []))
    table.add_row("N-gram Sizes", ", ".join(map(str, ngram_sizes)))
    return ngram_sizes


def _add_binlex_unique_signatures(
    table: Table, ngram_sizes: list[Any], unique_signatures: dict[str, Any]
) -> None:
    for n in ngram_sizes:
        if n in unique_signatures:
            table.add_row(f"Unique {n}-gram Signatures", str(unique_signatures[n]))


def _add_binlex_similarity_groups(
    table: Table, ngram_sizes: list[Any], similar_functions: dict[str, Any]
) -> None:
    for n in ngram_sizes:
        if n in similar_functions and similar_functions[n]:
            groups = similar_functions[n]
            table.add_row(f"Similar {n}-gram Groups", str(len(groups)))
            if groups:
                largest_group = groups[0]
                table.add_row(f"Largest {n}-gram Group", f"{largest_group['count']} functions")


def _add_binlex_binary_signatures(
    table: Table, ngram_sizes: list[Any], binary_signature: dict[str, Any]
) -> None:
    for n in ngram_sizes:
        if n in binary_signature:
            sig = binary_signature[n]
            table.add_row(f"Binary {n}-gram Signature", format_hash_display(sig, max_length=64))


def _add_binlex_top_ngrams(
    table: Table, ngram_sizes: list[Any], top_ngrams: dict[str, Any]
) -> None:
    for n in ngram_sizes:
        if n in top_ngrams and top_ngrams[n]:
            top_3 = top_ngrams[n][:3]
            ngram_strs = []
            for ngram, count in top_3:
                clean_ngram = ngram.replace("&nbsp;", " ").replace(HTML_AMP, "&").strip()
                if len(clean_ngram) > 50:
                    clean_ngram = clean_ngram[:47] + "..."
                ngram_strs.append(f"• {clean_ngram} ({count})")
            table.add_row(f"Top {n}-grams", "\n".join(ngram_strs))
