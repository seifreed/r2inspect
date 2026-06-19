"""Shared results-bucket helper for pipeline code."""

from __future__ import annotations

from typing import Any


def _results_bucket(context: dict[str, Any]) -> dict[str, Any]:
    results = context.get("results")
    if isinstance(results, dict):
        return results
    results = {}
    context["results"] = results
    return results
