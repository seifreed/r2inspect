#!/usr/bin/env python3
"""Recommendation rules for executive summaries."""

from __future__ import annotations

from typing import Any

RECOMMENDATION_RULES = [
    (
        lambda results: results["packer"].get("is_packed"),
        "File appears packed; consider unpacking before deeper analysis.",
    ),
    (
        lambda results: results["security"].get("authenticode") is False,
        "File is unsigned; verify source and integrity.",
    ),
    (
        lambda results: results["crypto"].get("matches"),
        "Cryptographic routines detected; check for encryption or obfuscation.",
    ),
    (
        lambda results: results["anti_analysis"].get("anti_debug"),
        "Anti-debugging detected; use anti-anti-debug techniques.",
    ),
]


def generate_recommendations(analysis_results: dict[str, Any]) -> list[str]:
    """Build the recommendation list for the executive summary."""
    recommendations = [
        message for predicate, message in RECOMMENDATION_RULES if predicate(analysis_results)
    ]
    return recommendations or ["No immediate concerns detected; proceed with standard analysis."]
