"""Apply explicit analyzer execution states to legacy result payloads."""

from __future__ import annotations

from typing import Any

from ..domain.results import AnalyzerExecution, AnalyzerStatus

_INVALID_VERDICT_STATES = {
    AnalyzerStatus.DEPENDENCY_UNAVAILABLE,
    AnalyzerStatus.FAILED,
    AnalyzerStatus.TIMED_OUT,
    AnalyzerStatus.UNSUPPORTED,
}
_VERDICT_FIELDS = {"detected", "is_packed", "anti_debug", "anti_vm"}


def normalize_analyzer_results(results: dict[str, Any]) -> dict[str, Any]:
    """Clear verdict fields only when an explicit execution state invalidates them."""
    executions = results.get("_analyzer_executions")
    if not isinstance(executions, list):
        return results
    for execution in executions:
        if isinstance(execution, dict):
            execution = AnalyzerExecution.from_dict(execution)
        if not isinstance(execution, AnalyzerExecution):
            continue
        if execution.status not in _INVALID_VERDICT_STATES:
            continue
        if isinstance(execution.data, dict):
            execution.data["status"] = execution.status.value
            for field in _VERDICT_FIELDS.intersection(execution.data):
                execution.data[field] = None
    return results


__all__ = ["normalize_analyzer_results"]
