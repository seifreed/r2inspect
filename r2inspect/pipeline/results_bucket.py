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


def merge_stage_results(target: dict[str, Any], stage_result: dict[str, Any]) -> None:
    """Merge a stage result while accumulating execution envelopes."""
    for key, value in stage_result.items():
        if key == "_analyzer_executions" and isinstance(value, list):
            existing = target.setdefault(key, [])
            if isinstance(existing, list):
                existing.extend(value)
                continue
        target[key] = value


__all__ = ["_results_bucket", "merge_stage_results"]
