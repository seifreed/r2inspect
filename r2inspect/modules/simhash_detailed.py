#!/usr/bin/env python3
"""Detailed SimHash analysis helpers."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from typing import Any

from ..abstractions.result_builder import init_result, mark_unavailable


def run_detailed_simhash_analysis(
    *,
    filepath: Any,
    simhash_available: bool,
    no_features_error: str,
    extract_string_features: Callable[[], list[str]],
    extract_opcodes_features: Callable[[], list[str]],
    extract_function_features: Callable[[], dict[str, Any]],
    find_similar_functions: Callable[[dict[str, Any]], list[dict[str, Any]]],
    log_debug: Callable[[str], None],
    log_error: Callable[[str], None],
) -> dict[str, Any]:
    """Run the detailed SimHash analysis flow."""
    if not simhash_available:
        result = init_result(
            additional_fields={"library_available": False},
            include_execution_time=False,
        )
        return mark_unavailable(result, "simhash library not installed")

    from simhash import Simhash

    log_debug(f"Starting detailed SimHash analysis for {filepath}")

    results: dict[str, Any] = init_result(
        additional_fields={
            "library_available": True,
            "binary_simhash": None,
            "strings_simhash": None,
            "opcodes_simhash": None,
            "combined_simhash": None,
            "function_simhashes": {},
            "total_functions": 0,
            "analyzed_functions": 0,
            "feature_stats": {},
            "similarity_groups": [],
        },
        include_execution_time=False,
    )

    try:
        # Extract features
        strings_features = extract_string_features()
        opcodes_features = extract_opcodes_features()
        function_features = extract_function_features()

        if not strings_features and not opcodes_features:
            results["error"] = no_features_error
            log_debug(no_features_error)
            return results

        # Calculate different SimHash variants
        results["available"] = True

        # Strings-only SimHash
        if strings_features:
            strings_simhash = Simhash(strings_features)
            results["strings_simhash"] = {
                "hash": strings_simhash.value,
                "hex": hex(strings_simhash.value),
                "binary": bin(strings_simhash.value),
                "feature_count": len(strings_features),
            }

        # Opcodes-only SimHash
        if opcodes_features:
            opcodes_simhash = Simhash(opcodes_features)
            results["opcodes_simhash"] = {
                "hash": opcodes_simhash.value,
                "hex": hex(opcodes_simhash.value),
                "binary": bin(opcodes_simhash.value),
                "feature_count": len(opcodes_features),
            }

        # Combined SimHash (strings + opcodes)
        combined_features = strings_features + opcodes_features
        if combined_features:
            combined_simhash = Simhash(combined_features)
            results["combined_simhash"] = {
                "hash": combined_simhash.value,
                "hex": hex(combined_simhash.value),
                "binary": bin(combined_simhash.value),
                "feature_count": len(combined_features),
            }
            results["binary_simhash"] = results["combined_simhash"]  # Alias

        # Function-level SimHashes
        if function_features:
            results["function_simhashes"] = function_features
            results["total_functions"] = len(
                [f for f in function_features.values() if f.get("simhash")]
            )
            results["analyzed_functions"] = len(
                [f for f in function_features.values() if f.get("simhash")]
            )

            # Find similar functions
            similar_groups = find_similar_functions(function_features)
            results["similarity_groups"] = similar_groups

        # Feature statistics
        feature_stats: dict[str, Any] = {
            "total_strings": len(strings_features),
            "total_opcodes": len(opcodes_features),
            "total_features": len(combined_features),
            "unique_strings": len(set(strings_features)) if strings_features else 0,
            "unique_opcodes": len(set(opcodes_features)) if opcodes_features else 0,
        }

        # Add frequency analysis
        if combined_features:
            feature_counter = Counter(combined_features)
            feature_stats["most_common_features"] = feature_counter.most_common(10)
            feature_stats["feature_diversity"] = len(set(combined_features)) / len(
                combined_features
            )

        results["feature_stats"] = feature_stats

        log_debug(f"SimHash analysis completed: {len(combined_features)} total features")
        log_debug(f"Binary SimHash: {hex(combined_simhash.value) if combined_features else 'N/A'}")

    except Exception as e:
        log_error(f"SimHash analysis failed: {e}")
        results["error"] = str(e)

    return results
