#!/usr/bin/env python3
"""Recommendation rules for executive summaries."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..abstractions.coercion_support import get_dict_bucket

RecommendationPredicate = Callable[[dict[str, Any]], Any]

RECOMMENDATION_RULES: list[tuple[RecommendationPredicate, str]] = [
    (
        lambda results: get_dict_bucket(results, "packer").get("is_packed"),
        "File appears packed; consider unpacking before deeper analysis.",
    ),
    (
        lambda results: get_dict_bucket(results, "security").get("authenticode") is False,
        "File is unsigned; verify source and integrity.",
    ),
    (
        lambda results: any(
            get_dict_bucket(results, "crypto").get(key)
            for key in ("matches", "algorithms", "constants", "functions")
        ),
        "Cryptographic routines detected; check for encryption or obfuscation.",
    ),
    (
        lambda results: get_dict_bucket(results, "anti_analysis").get("anti_debug"),
        "Anti-debugging detected; use anti-anti-debug techniques.",
    ),
]


def generate_recommendations(analysis_results: dict[str, Any]) -> list[str]:
    """Build the recommendation list for the executive summary."""
    recommendations = [
        message for predicate, message in RECOMMENDATION_RULES if predicate(analysis_results)
    ]
    return recommendations or ["No immediate concerns detected; proceed with standard analysis."]
