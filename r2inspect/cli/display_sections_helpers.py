#!/usr/bin/env python3
"""Helper functions for display section rendering."""

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
        table.add_row(
            "Additional Groups",
            f"... and {len(similarity_groups) - 3} more groups",
        )


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
            table.add_row(
                "Section Names",
                f"{', '.join(displayed)}\n... and {remaining} more",
            )
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
