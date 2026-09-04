"""Analyzer execution projection for report/v1."""

from __future__ import annotations

from typing import Any

from ..domain.results import AnalyzerExecution, TypedAnalyzerResult
from ..schemas.report_v1 import (
    AnalyzerErrorV1,
    AnalyzerOutcomeV1,
    AnalyzerStatus,
    AnalyzerWarningV1,
)


def _status(value: dict[str, Any]) -> AnalyzerStatus:
    explicit = value.get("status")
    if isinstance(explicit, str):
        try:
            return AnalyzerStatus(explicit)
        except ValueError:
            pass
    if value.get("library_available") is False:
        return AnalyzerStatus.DEPENDENCY_UNAVAILABLE
    if value.get("error") or value.get("available") is False:
        return AnalyzerStatus.FAILED
    return (
        AnalyzerStatus.NOT_DETECTED if value.get("detected") is False else AnalyzerStatus.COMPLETED
    )


def _outcome_metrics(value: dict[str, Any]) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    detected = value.get("detected")
    if isinstance(detected, bool):
        metrics["detected"] = detected
    for key in ("peak_memory_mb", "memory_mb", "rss_mb"):
        memory = value.get(key)
        if isinstance(memory, int | float) and not isinstance(memory, bool):
            metrics["peak_memory_mb"] = float(memory)
            break
    return metrics


def _execution_outcomes(
    executions: list[AnalyzerExecution[Any]],
) -> list[AnalyzerOutcomeV1]:
    return [
        AnalyzerOutcomeV1(
            analyzer_id=execution.analyzer_id,
            analyzer_version=execution.analyzer_version,
            output_schema=execution.output_schema,
            status=execution.status,
            duration=execution.duration,
            error="; ".join(error.message for error in execution.errors) or None,
            errors=[
                AnalyzerErrorV1(
                    code=error.code,
                    component=error.component,
                    message=error.message,
                    recoverable=error.recoverable,
                )
                for error in execution.errors
            ],
            warnings=[AnalyzerWarningV1(**warning.to_dict()) for warning in execution.warnings],
            metrics=execution.metrics,
        )
        for execution in executions
    ]


def _typed_outcome(analyzer_id: str, value: TypedAnalyzerResult) -> AnalyzerOutcomeV1:
    status = value.status
    error = value.error
    if status == "completed" and not error and value.get("error"):
        status = _status(value).value
        error = str(value.get("error"))
    try:
        typed_status = AnalyzerStatus(status)
    except ValueError:
        typed_status = _status(value)
    duration = value.get("execution_time", 0.0)
    metrics = dict(value.metrics)
    metrics.update(_outcome_metrics(value))
    return AnalyzerOutcomeV1(
        analyzer_id=value.analyzer_id or analyzer_id,
        status=typed_status,
        duration=float(duration) if isinstance(duration, int | float) else 0.0,
        error=error,
        metrics=metrics,
    )


def _legacy_outcomes(raw: dict[str, Any]) -> list[AnalyzerOutcomeV1]:
    outcomes = []
    for analyzer_id, value in sorted(raw.items()):
        if isinstance(value, TypedAnalyzerResult):
            outcomes.append(_typed_outcome(analyzer_id, value))
        elif isinstance(value, dict) and {
            "available",
            "error",
            "execution_time",
        }.intersection(value):
            duration = value.get("execution_time", 0.0)
            error = value.get("error")
            outcomes.append(
                AnalyzerOutcomeV1(
                    analyzer_id=analyzer_id,
                    status=_status(value),
                    duration=(float(duration) if isinstance(duration, int | float) else 0.0),
                    error=str(error) if error else None,
                    metrics=_outcome_metrics(value),
                )
            )
    return outcomes


def _merge_status_sidecar(
    outcomes: list[AnalyzerOutcomeV1], sidecar: Any
) -> list[AnalyzerOutcomeV1]:
    if not isinstance(sidecar, dict):
        return outcomes
    existing = {outcome.analyzer_id: outcome for outcome in outcomes}
    for analyzer_id, value in sorted(sidecar.items()):
        if not isinstance(value, dict):
            continue
        metrics = value.get("metrics", {})
        if analyzer_id in existing:
            if isinstance(metrics, dict):
                existing[analyzer_id].metrics.update(metrics)
            continue
        duration = value.get("duration", 0.0)
        error = value.get("error")
        outcomes.append(
            AnalyzerOutcomeV1(
                analyzer_id=str(analyzer_id),
                status=_status(value),
                duration=float(duration) if isinstance(duration, int | float) else 0.0,
                error=str(error) if error else None,
                metrics=metrics if isinstance(metrics, dict) else {},
            )
        )
    return outcomes


def analyzer_outcomes(
    raw: dict[str, Any], executions: list[AnalyzerExecution[Any]] | None = None
) -> list[AnalyzerOutcomeV1]:
    """Project authoritative execution envelopes, with a legacy fallback."""
    if executions:
        return _execution_outcomes(executions)
    return _merge_status_sidecar(_legacy_outcomes(raw), raw.get("_analyzer_status"))


__all__ = ["analyzer_outcomes"]
