#!/usr/bin/env python3
"""SimHash display support helpers."""

from __future__ import annotations

from typing import Any

from rich.table import Table

from .display_base import ANALYZED_FUNCTIONS_LABEL, SIMILAR_GROUPS_LABEL, TOTAL_FUNCTIONS_LABEL
from .display_sections_common import add_group_functions_row


def _coerce_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _coerce_text(value: Any) -> str:
    return value if isinstance(value, str) else str(value if value is not None else "")


def _add_simhash_feature_stats(table: Table, feature_stats: dict[str, Any]) -> None:
    if not isinstance(feature_stats, dict):
        return
    total_features = feature_stats.get("total_features", 0)
    total_strings = feature_stats.get("total_strings", 0)
    total_opcodes = feature_stats.get("total_opcodes", 0)

    table.add_row("Total Features", str(total_features))
    table.add_row("String Features", str(total_strings))
    table.add_row("Opcode Features", str(total_opcodes))

    feature_diversity = feature_stats.get("feature_diversity", 0.0)
    table.add_row("Feature Diversity", f"{_coerce_float(feature_diversity):.3f}")


def _format_simhash_hex(hash_hex: str) -> str:
    if len(hash_hex) > 32:
        return f"{hash_hex[:32]}\n{hash_hex[32:]}"
    return hash_hex


def _add_simhash_hashes(table: Table, simhash_info: dict[str, Any]) -> None:
    combined_simhash = simhash_info.get("combined_simhash")
    if isinstance(combined_simhash, dict):
        hash_hex = combined_simhash.get("hex", "")
        table.add_row("Binary SimHash", _format_simhash_hex(hash_hex))
        table.add_row("Combined Features", str(combined_simhash.get("feature_count", 0)))

    strings_simhash = simhash_info.get("strings_simhash")
    if isinstance(strings_simhash, dict):
        hash_hex = strings_simhash.get("hex", "")
        table.add_row("Strings SimHash", _format_simhash_hex(hash_hex))

    opcodes_simhash = simhash_info.get("opcodes_simhash")
    if isinstance(opcodes_simhash, dict):
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
    if not isinstance(similarity_groups, list) or not similarity_groups:
        table.add_row(SIMILAR_GROUPS_LABEL, "0 (all functions unique)")
        return

    _add_simhash_similarity_groups(table, similarity_groups)


def _add_simhash_similarity_groups(table: Table, similarity_groups: list[dict[str, Any]]) -> None:
    if not isinstance(similarity_groups, list):
        return
    table.add_row(SIMILAR_GROUPS_LABEL, str(len(similarity_groups)))
    for i, group in enumerate(similarity_groups[:3]):
        _add_simhash_similarity_group(table, i + 1, group)

    if len(similarity_groups) > 3:
        table.add_row("Additional Groups", f"... and {len(similarity_groups) - 3} more groups")


def _add_simhash_similarity_group(table: Table, index: int, group: dict[str, Any]) -> None:
    if not isinstance(group, dict):
        return
    group_size = group.get("count", 0)
    group_hash = _coerce_text(group.get("representative_hash", ""))
    hash_display = f"{group_hash[:24]}...{group_hash[-8:]}" if len(group_hash) > 24 else group_hash

    table.add_row(f"Group {index} Size", f"{group_size} functions")
    table.add_row(f"Group {index} Hash", hash_display)

    add_group_functions_row(table, group, index)


def _add_simhash_top_features(table: Table, feature_stats: dict[str, Any]) -> None:
    most_common = feature_stats.get("most_common_features", [])
    if not isinstance(most_common, list) or not most_common:
        return

    top_features = []
    for item in most_common[:5]:
        if not isinstance(item, (list, tuple)) or len(item) < 2:
            continue
        feature, count = item[0], item[1]
        clean_feature = str(feature).replace("STR:", "").replace("OP:", "").replace("OPTYPE:", "")
        if len(clean_feature) > 40:
            clean_feature = clean_feature[:37] + "..."
        top_features.append(f"• {clean_feature} ({count})")

    table.add_row("Top Features", "\n".join(top_features))
