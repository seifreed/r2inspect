#!/usr/bin/env python3
"""Detailed SimHash analysis helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..abstractions.result_builder import init_result, mark_unavailable
from ..domain.services.simhash import build_feature_stats


def _simhash_entry(features: list[str], simhash_cls: Any) -> dict[str, Any]:
    value = simhash_cls(features).value
    return {
        "hash": value,
        "hex": hex(value),
        "binary": bin(value),
        "feature_count": len(features),
    }


def _add_function_simhashes(
    results: dict[str, Any],
    function_features: dict[str, Any],
    find_similar_functions: Callable[[dict[str, Any]], list[dict[str, Any]]],
) -> None:
    if not function_features:
        return
    results["function_simhashes"] = function_features
    results["total_functions"] = len(function_features)
    results["analyzed_functions"] = len([f for f in function_features.values() if f.get("simhash")])
    results["similarity_groups"] = find_similar_functions(function_features)


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

        if strings_features:
            results["strings_simhash"] = _simhash_entry(strings_features, Simhash)

        if opcodes_features:
            results["opcodes_simhash"] = _simhash_entry(opcodes_features, Simhash)

        combined_features = strings_features + opcodes_features
        if combined_features:
            results["combined_simhash"] = _simhash_entry(combined_features, Simhash)
            results["binary_simhash"] = results["combined_simhash"]  # Alias

        _add_function_simhashes(results, function_features, find_similar_functions)

        # Feature statistics
        results["feature_stats"] = build_feature_stats(strings_features, opcodes_features)

        combined_hex = results["combined_simhash"]["hex"] if combined_features else "N/A"
        log_debug(f"SimHash analysis completed: {len(combined_features)} total features")
        log_debug(f"Binary SimHash: {combined_hex}")

    except Exception as e:
        log_error(f"SimHash analysis failed: {e}")
        results["error"] = str(e)

    return results
