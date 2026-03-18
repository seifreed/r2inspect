#!/usr/bin/env python3
"""Binbloom display helpers."""

from __future__ import annotations

import re
from typing import Any

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


def _display_binbloom(results: Results) -> None:
    binbloom_info, present = _get_section(results, "binbloom", {})
    if not present:
        return
    table = Table(title="Binbloom (Bloom Filter Analysis)", show_header=True, width=120)
    table.add_column("Property", style="cyan", width=25)
    table.add_column("Value", style="yellow", width=90, overflow="fold")

    if binbloom_info.get("available"):
        _add_binbloom_stats(table, binbloom_info)
        _add_binbloom_similar_groups(table, binbloom_info)
        _add_binbloom_binary_signature(table, binbloom_info)
        _add_binbloom_bloom_stats(table, binbloom_info)
        table.add_row("Status", STATUS_AVAILABLE)
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if binbloom_info.get("error"):
            table.add_row("Error", binbloom_info.get("error", UNKNOWN_ERROR))
        elif not binbloom_info.get("library_available", True):
            table.add_row("Error", "pybloom-live library not installed")
            table.add_row("Install Command", "pip install pybloom-live")

    _get_console().print(table)
    _display_binbloom_signature_details(binbloom_info)
    _get_console().print()


def _add_binbloom_stats(table: Table, binbloom_info: dict[str, Any]) -> None:
    total_functions = binbloom_info.get("total_functions", 0)
    table.add_row(TOTAL_FUNCTIONS_LABEL, str(total_functions))

    analyzed_functions = binbloom_info.get("analyzed_functions", 0)
    table.add_row(ANALYZED_FUNCTIONS_LABEL, str(analyzed_functions))

    capacity = binbloom_info.get("capacity", 0)
    error_rate = binbloom_info.get("error_rate", 0.0)
    table.add_row("Bloom Filter Capacity", str(capacity))
    table.add_row("False Positive Rate", f"{error_rate:.4f} ({error_rate * 100:.2f}%)")

    unique_signatures = binbloom_info.get("unique_signatures", 0)
    diversity_ratio = (unique_signatures / analyzed_functions * 100) if analyzed_functions else 0
    table.add_row(
        "Unique Function Signatures",
        f"{unique_signatures} ({diversity_ratio:.1f}% diversity)",
    )

    function_signatures = binbloom_info.get("function_signatures", {})
    if not function_signatures:
        return

    total_instructions = sum(
        sig.get("instruction_count", 0) for sig in function_signatures.values()
    )
    avg_instructions = total_instructions / len(function_signatures) if function_signatures else 0
    unique_instructions = sum(
        sig.get("unique_instructions", 0) for sig in function_signatures.values()
    )
    avg_unique = unique_instructions / len(function_signatures) if function_signatures else 0

    table.add_row("Avg Instructions/Function", f"{avg_instructions:.1f}")
    table.add_row("Avg Unique Instructions", f"{avg_unique:.1f}")


def _add_binbloom_similar_groups(table: Table, binbloom_info: dict[str, Any]) -> None:
    similar_functions = binbloom_info.get("similar_functions", [])
    if not similar_functions:
        table.add_row(SIMILAR_GROUPS_LABEL, "0 (all functions unique)")
        return

    table.add_row(SIMILAR_GROUPS_LABEL, str(len(similar_functions)))
    for i, group in enumerate(similar_functions[:3]):
        _add_binbloom_group(table, i + 1, group)

    if len(similar_functions) > 3:
        table.add_row("Additional Groups", f"... and {len(similar_functions) - 3} more groups")


def _add_binbloom_group(table: Table, index: int, group: dict[str, Any]) -> None:
    group_size = group.get("count", 0)
    group_signature = group.get("signature", "")
    group_sig = group_signature[:32] + "..." if len(group_signature) > 32 else group_signature

    table.add_row(f"Group {index} Size", f"{group_size} functions")
    table.add_row(f"Group {index} Signature", group_sig)

    if not group.get("functions"):
        return

    sample_funcs = group["functions"][:5]
    func_display = []
    for func in sample_funcs:
        func_name = func if len(func) <= 30 else func[:27] + "..."
        func_display.append(f"• {func_name}")

    if len(group["functions"]) > 5:
        func_display.append(f"• ... and {len(group['functions']) - 5} more")

    table.add_row(f"Group {index} Functions", "\n".join(func_display))


def _add_binbloom_binary_signature(table: Table, binbloom_info: dict[str, Any]) -> None:
    binary_signature = binbloom_info.get("binary_signature")
    if binary_signature:
        table.add_row(
            "Binary Bloom Signature", format_hash_display(binary_signature, max_length=64)
        )


def _add_binbloom_bloom_stats(table: Table, binbloom_info: dict[str, Any]) -> None:
    bloom_stats = binbloom_info.get("bloom_stats", {})
    if not bloom_stats:
        return

    avg_fill_rate = bloom_stats.get("average_fill_rate", 0.0)
    table.add_row("Average Fill Rate", f"{avg_fill_rate:.4f} ({avg_fill_rate * 100:.2f}%)")

    total_filters = bloom_stats.get("total_filters", 0)
    table.add_row("Total Bloom Filters", str(total_filters))


def _display_binbloom_signature_details(binbloom_info: dict[str, Any]) -> None:
    if not binbloom_info.get("available"):
        return
    if binbloom_info.get("unique_signatures", 0) <= 1:
        return

    function_signatures = binbloom_info.get("function_signatures", {})
    signatures_by_hash: dict[str, list[str]] = {}
    for func_name, sig_data in function_signatures.items():
        sig_hash = sig_data.get("signature", "")
        signatures_by_hash.setdefault(sig_hash, []).append(func_name)

    sig_table = Table(
        title="Binbloom Signature Details",
        show_header=True,
        header_style="bold cyan",
        title_style="bold cyan",
        expand=True,
    )
    sig_table.add_column("Signature #", style="yellow", no_wrap=True, width=13)
    sig_table.add_column("Hash", style="green", min_width=50, overflow="fold")
    sig_table.add_column("Functions", style="blue", min_width=45, overflow="fold")

    unique_sigs = list(signatures_by_hash.keys())[:5]
    for i, sig_hash in enumerate(unique_sigs):
        funcs = signatures_by_hash[sig_hash]
        clean_funcs = [re.sub(r"&nbsp;?", " ", func).replace(HTML_AMP, "&") for func in funcs[:3]]
        func_list = ", ".join(clean_funcs) + ("..." if len(funcs) > 3 else "")
        sig_table.add_row(
            f"Signature {i + 1}",
            f"{sig_hash[:64]}{'...' if len(sig_hash) > 64 else ''}",
            f"Functions ({len(funcs)}): {func_list}",
        )

    _get_console().print()
    _get_console().print(sig_table)
