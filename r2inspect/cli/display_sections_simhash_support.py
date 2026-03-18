#!/usr/bin/env python3
"""SimHash display support helpers."""

from __future__ import annotations

from typing import Any

from rich.table import Table

from .display_base import ANALYZED_FUNCTIONS_LABEL, SIMILAR_GROUPS_LABEL, TOTAL_FUNCTIONS_LABEL


def _add_simhash_feature_stats(table: Table, feature_stats: dict[str, Any]) -> None:
    total_features = feature_stats.get("total_features", 0)
    total_strings = feature_stats.get("total_strings", 0)
    total_opcodes = feature_stats.get("total_opcodes", 0)

    table.add_row("Total Features", str(total_features))
    table.add_row("String Features", str(total_strings))
    table.add_row("Opcode Features", str(total_opcodes))

    feature_diversity = feature_stats.get("feature_diversity", 0.0)
    table.add_row("Feature Diversity", f"{feature_diversity:.3f}")


def _format_simhash_hex(hash_hex: str) -> str:
    if len(hash_hex) > 32:
        return f"{hash_hex[:32]}\n{hash_hex[32:]}"
    return hash_hex


def _add_simhash_hashes(table: Table, simhash_info: dict[str, Any]) -> None:
    combined_simhash = simhash_info.get("combined_simhash")
    if combined_simhash:
        hash_hex = combined_simhash.get("hex", "")
        table.add_row("Binary SimHash", _format_simhash_hex(hash_hex))
        table.add_row("Combined Features", str(combined_simhash.get("feature_count", 0)))

    strings_simhash = simhash_info.get("strings_simhash")
    if strings_simhash:
        hash_hex = strings_simhash.get("hex", "")
        table.add_row("Strings SimHash", _format_simhash_hex(hash_hex))

    opcodes_simhash = simhash_info.get("opcodes_simhash")
    if opcodes_simhash:
        hash_hex = opcodes_simhash.get("hex", "")
        table.add_row("Opcodes SimHash", _format_simhash_hex(hash_hex))


def _add_simhash_function_analysis(table: Table, simhash_info: dict[str, Any]) -> None:
    function_simhashes = simhash_info.get("function_simhashes", {})
    if not function_simhashes:
        return

    total_functions = simhash_info.get("total_functions", 0)
    analyzed_functions = simhash_info.get("analyzed_functions", 0)
    table.add_row(TOTAL_FUNCTIONS_LABEL, str(total_functions))
    table.add_row(ANALYZED_FUNCTIONS_LABEL, str(analyzed_functions))

    similarity_groups = simhash_info.get("similarity_groups", [])
    if not similarity_groups:
        table.add_row(SIMILAR_GROUPS_LABEL, "0 (all functions unique)")
        return

    _add_simhash_similarity_groups(table, similarity_groups)


def _add_simhash_similarity_groups(table: Table, similarity_groups: list[dict[str, Any]]) -> None:
    table.add_row(SIMILAR_GROUPS_LABEL, str(len(similarity_groups)))
    for i, group in enumerate(similarity_groups[:3]):
        _add_simhash_similarity_group(table, i + 1, group)

    if len(similarity_groups) > 3:
        table.add_row("Additional Groups", f"... and {len(similarity_groups) - 3} more groups")


def _add_simhash_similarity_group(table: Table, index: int, group: dict[str, Any]) -> None:
    group_size = group.get("count", 0)
    group_hash = group.get("representative_hash", "")
    hash_display = f"{group_hash[:24]}...{group_hash[-8:]}" if len(group_hash) > 24 else group_hash

    table.add_row(f"Group {index} Size", f"{group_size} functions")
    table.add_row(f"Group {index} Hash", hash_display)

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


def _add_simhash_top_features(table: Table, feature_stats: dict[str, Any]) -> None:
    most_common = feature_stats.get("most_common_features", [])
    if not most_common:
        return

    top_features = []
    for feature, count in most_common[:5]:
        clean_feature = feature.replace("STR:", "").replace("OP:", "").replace("OPTYPE:", "")
        if len(clean_feature) > 40:
            clean_feature = clean_feature[:37] + "..."
        top_features.append(f"• {clean_feature} ({count})")

    table.add_row("Top Features", "\n".join(top_features))
