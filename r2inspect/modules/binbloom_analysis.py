#!/usr/bin/env python3
"""Binbloom analysis helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from ..domain.services.binbloom import build_binbloom_result, count_unique_signatures


def _resolve_analyzer_name(analyzer: Any) -> str:
    getter = getattr(analyzer, "get_name", None)
    if callable(getter):
        return str(getter())
    return str(analyzer.__class__.__name__).lower()


def _resolve_unique_signatures(analyzer: Any, function_signatures: dict[str, Any]) -> int:
    collector = getattr(analyzer, "_collect_unique_signatures", None)
    if callable(collector):
        return len(collector(function_signatures))
    return count_unique_signatures(function_signatures)


def run_binbloom_analysis(
    *,
    analyzer: Any,
    capacity: int | None,
    error_rate: float | None,
    bloom_available: bool,
    log_debug: Callable[[str], None],
    log_error: Callable[[str], None],
) -> dict[str, Any]:
    """Run Binbloom analysis using the analyzer instance."""
    result = build_binbloom_result(
        _resolve_analyzer_name(analyzer),
        capacity=capacity or analyzer.default_capacity,
        error_rate=error_rate or analyzer.default_error_rate,
    )

    if not bloom_available:
        return cast(
            dict[str, Any],
            analyzer._mark_unavailable(
                result,
                "pybloom-live library not installed",
                library_available=False,
            ),
        )

    if capacity is None:
        capacity = analyzer.default_capacity
    if error_rate is None:
        error_rate = analyzer.default_error_rate

    log_debug(f"Starting Binbloom analysis for {analyzer.filepath}")

    results = result

    try:
        # Extract all functions
        functions = analyzer._extract_functions()
        if not functions:
            results["error"] = "No functions found in binary"
            log_debug("No functions found in binary")
            return results

        results["total_functions"] = len(functions)
        log_debug(f"Found {len(functions)} functions to analyze")

        function_blooms, function_signatures, all_instructions, analyzed_count = (
            analyzer._collect_function_blooms(functions, capacity, error_rate)
        )

        if not function_blooms:
            results["error"] = "No functions could be analyzed for Binbloom"
            log_debug("No functions could be analyzed for Binbloom")
            return results

        # Analyze results
        results["available"] = True
        results["function_blooms"] = analyzer._serialize_blooms(function_blooms)
        results["function_signatures"] = function_signatures
        results["analyzed_functions"] = analyzed_count

        # Calculate unique signatures
        results["unique_signatures"] = _resolve_unique_signatures(analyzer, function_signatures)

        # Find similar functions (same signature)
        similar_functions = analyzer._find_similar_functions(function_signatures)
        results["similar_functions"] = similar_functions

        # Create binary-wide Bloom filter
        analyzer._add_binary_bloom(results, all_instructions, capacity, error_rate)

        # Calculate Bloom filter statistics
        bloom_stats = analyzer._calculate_bloom_stats(function_blooms, capacity, error_rate)
        results["bloom_stats"] = bloom_stats

        log_debug(
            f"Binbloom analysis completed: {analyzed_count}/{len(functions)} functions analyzed"
        )
        log_debug(
            f"Found {results['unique_signatures']} unique signatures, {len(similar_functions)} similar function groups"
        )

    except Exception as e:
        log_error(f"Binbloom analysis failed: {e}")
        results["error"] = str(e)

    return results
