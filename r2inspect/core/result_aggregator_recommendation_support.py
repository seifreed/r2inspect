#!/usr/bin/env python3
"""Recommendation rules for executive summaries."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

RecommendationPredicate = Callable[[dict[str, Any]], Any]


def _bucket(results: dict[str, Any], key: str) -> dict[str, Any]:
    value = results.get(key)
    return value if isinstance(value, dict) else {}


RECOMMENDATION_RULES: list[tuple[RecommendationPredicate, str]] = [
    (
        lambda results: _bucket(results, "packer").get("is_packed"),
        "File appears packed; consider unpacking before deeper analysis.",
    ),
    (
        lambda results: _bucket(results, "security").get("authenticode") is False,
        "File is unsigned; verify source and integrity.",
    ),
    (
        lambda results: _bucket(results, "crypto").get("matches"),
        "Cryptographic routines detected; check for encryption or obfuscation.",
    ),
    (
        lambda results: _bucket(results, "anti_analysis").get("anti_debug"),
        "Anti-debugging detected; use anti-anti-debug techniques.",
    ),
]


def generate_recommendations(analysis_results: dict[str, Any]) -> list[str]:
    """Build the recommendation list for the executive summary."""
    if not isinstance(analysis_results, dict):
        return ["No immediate concerns detected; proceed with standard analysis."]
    recommendations = [
        message for predicate, message in RECOMMENDATION_RULES if predicate(analysis_results)
    ]
    return recommendations or ["No immediate concerns detected; proceed with standard analysis."]
