"""Typed analyzer metadata projection for report/v1."""

from __future__ import annotations

from typing import Any

from ..domain.results import TypedAnalyzerResult


def typed_analyzer_statuses(raw: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Extract execution metadata from mapping-compatible typed results."""
    statuses: dict[str, dict[str, Any]] = {}
    for analyzer_id, value in raw.items():
        if not isinstance(value, TypedAnalyzerResult):
            continue
        status: dict[str, Any] = {"status": value.status}
        if value.error:
            status["error"] = value.error
        duration = value.get("execution_time")
        if isinstance(duration, int | float) and not isinstance(duration, bool):
            status["duration"] = float(duration)
        metrics = dict(value.metrics)
        detected = value.get("detected")
        if isinstance(detected, bool):
            metrics["detected"] = detected
        if metrics:
            status["metrics"] = metrics
        statuses[analyzer_id] = status
    return statuses
