"""Universal analyzer execution envelopes for pipeline stages."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from ..domain.results import (
    AnalyzerError,
    AnalyzerExecution,
    AnalyzerStatus,
    AnalyzerWarning,
    TypedAnalyzerResult,
    analyzer_status_from_payload,
)
from ..infrastructure.logging import get_logger
from .results_bucket import _results_bucket

logger = get_logger(__name__)

_RECOVERABLE_STATUSES = {
    AnalyzerStatus.COMPLETED_WITH_WARNINGS,
    AnalyzerStatus.PARTIAL,
    AnalyzerStatus.NOT_APPLICABLE,
    AnalyzerStatus.UNSUPPORTED,
    AnalyzerStatus.DEPENDENCY_UNAVAILABLE,
    AnalyzerStatus.SKIPPED_BY_PROFILE,
}


def _typed_result(
    analyzer_name: str, data: Any, *, status: str = "completed", error: str | None = None
) -> Any:
    """Attach typed metadata while preserving the legacy mapping contract."""
    if isinstance(data, TypedAnalyzerResult) or not isinstance(data, dict):
        return data
    return TypedAnalyzerResult(data, analyzer_id=analyzer_name, status=status, error=error)


def _record_analyzer_status(
    context: dict[str, Any], analyzer_name: str, *, status: str, error: str | None = None
) -> None:
    bucket = _results_bucket(context)
    statuses = bucket.setdefault("_analyzer_status", {})
    if not isinstance(statuses, dict):
        statuses = {}
        bucket["_analyzer_status"] = statuses
    payload: dict[str, Any] = {"status": status}
    if error:
        payload["error"] = error
    statuses[analyzer_name] = payload


def _record_analyzer_execution(context: dict[str, Any], execution: AnalyzerExecution[Any]) -> None:
    bucket = _results_bucket(context)
    executions = bucket.setdefault("_analyzer_executions", [])
    if not isinstance(executions, list):
        executions = []
        bucket["_analyzer_executions"] = executions
    executions.append(execution)


def _status_from(data: Any, explicit: Any = None, error: Any = None) -> AnalyzerStatus:
    typed_explicit = data.status if isinstance(data, TypedAnalyzerResult) else explicit
    del error
    return analyzer_status_from_payload(data, typed_explicit)


def _has_usable_data(data: Any) -> bool:
    if isinstance(data, dict):
        metadata = {
            "available",
            "detected",
            "error",
            "execution_time",
            "library_available",
            "status",
        }
        return any(
            key not in metadata and value not in (None, [], {}) for key, value in data.items()
        )
    return bool(data) if isinstance(data, (list, tuple, set)) else data is not None


def _execution_identity(stage: Any, analyzer_name: str) -> tuple[str, str | None]:
    get_metadata = getattr(getattr(stage, "registry", None), "get_metadata", None)
    metadata = get_metadata(analyzer_name) if callable(get_metadata) else None
    if metadata is None:
        return "unknown", None
    return str(metadata.version or "unknown"), metadata.output_schema


def _execution_error(
    analyzer_id: str, status: AnalyzerStatus, message: str, *, recoverable: bool = False
) -> AnalyzerError:
    return AnalyzerError(status.value.upper(), analyzer_id, message, recoverable)


def _structured_issues(
    analyzer_id: str, data: Any
) -> tuple[list[AnalyzerError], list[AnalyzerWarning]]:
    """Read wire-shaped issues without depending on the payload data type."""
    if not isinstance(data, dict):
        return [], []
    errors = [
        AnalyzerError(
            code=str(item.get("code", "ANALYZER_ERROR")),
            component=str(item.get("component", analyzer_id)),
            message=str(item.get("message", "Analyzer error")),
            recoverable=bool(item.get("recoverable", False)),
        )
        for item in data.get("errors", [])
        if isinstance(item, dict)
    ]
    warnings = [
        AnalyzerWarning(
            code=str(item.get("code", "ANALYZER_WARNING")),
            component=str(item.get("component", analyzer_id)),
            message=str(item.get("message", "Analyzer warning")),
        )
        for item in data.get("warnings", [])
        if isinstance(item, dict)
    ]
    return errors, warnings


def record_analyzer_execution(
    stage: Any,
    context: dict[str, Any],
    analyzer_name: str,
    data: Any,
    *,
    status: AnalyzerStatus | str | None = None,
    error: str | None = None,
    duration: float | None = None,
) -> AnalyzerExecution[Any]:
    typed_status = _status_from(data, status, error)
    analyzer_id = analyzer_name
    version, output_schema = _execution_identity(stage, analyzer_name)
    structured_errors, structured_warnings = _structured_issues(analyzer_id, data)
    if error:
        structured_errors.insert(
            0,
            _execution_error(
                analyzer_id,
                typed_status,
                error,
                recoverable=typed_status in _RECOVERABLE_STATUSES,
            ),
        )
    raw_duration = data.get("execution_time") if isinstance(data, dict) else None
    execution: AnalyzerExecution[Any] = AnalyzerExecution(
        analyzer_id=analyzer_id,
        analyzer_version=version,
        output_schema=output_schema,
        status=typed_status,
        data=data,
        errors=structured_errors,
        warnings=structured_warnings,
        duration=(
            float(raw_duration)
            if isinstance(raw_duration, (int, float)) and not isinstance(raw_duration, bool)
            else float(duration or 0.0)
        ),
        metrics=dict(data.metrics) if isinstance(data, TypedAnalyzerResult) else {},
    )
    _record_analyzer_execution(context, execution)
    if error or typed_status != AnalyzerStatus.COMPLETED:
        _record_analyzer_status(context, analyzer_id, status=typed_status.value, error=error)
    return execution


def record_skipped_execution(
    stage: Any,
    context: dict[str, Any],
    analyzer_name: str,
    status: AnalyzerStatus,
    message: str,
) -> None:
    version, output_schema = _execution_identity(stage, analyzer_name)
    execution: AnalyzerExecution[Any] = AnalyzerExecution(
        analyzer_id=analyzer_name,
        analyzer_version=version,
        output_schema=output_schema,
        status=status,
        errors=[_execution_error(analyzer_name, status, message, recoverable=True)],
    )
    _record_analyzer_execution(context, execution)
    _record_analyzer_status(context, analyzer_name, status=status.value, error=message)


def _collect_issues(
    analyzer: Any, analyzer_name: str, data: Any
) -> tuple[Any, str | None, list[AnalyzerError], list[AnalyzerWarning]]:
    status = getattr(analyzer, "last_status", None)
    error = getattr(analyzer, "last_error", None)
    analysis_errors = getattr(analyzer, "_analysis_errors", None)
    errors: list[AnalyzerError] = []
    if isinstance(analysis_errors, list) and analysis_errors:
        if status in (None, AnalyzerStatus.COMPLETED.value):
            status = "partial" if _has_usable_data(data) else "failed"
        error_status = AnalyzerStatus(str(status))
        errors = [
            _execution_error(
                analyzer_name,
                error_status,
                str(item),
                recoverable=error_status == AnalyzerStatus.PARTIAL,
            )
            for item in analysis_errors
        ]
        error = "; ".join(item.message for item in errors)
    warnings = getattr(analyzer, "_analysis_warnings", None)
    structured_warnings = (
        [AnalyzerWarning("ANALYZER_WARNING", analyzer_name, str(item)) for item in warnings]
        if isinstance(warnings, list)
        else []
    )
    return status, str(error) if error else None, errors, structured_warnings


def _store_success(
    stage: Any,
    context: dict[str, Any],
    analyzer_name: str,
    result_key: str,
    data: Any,
    analyzer: Any,
    started: float,
) -> dict[str, Any]:
    status, error, errors, warnings = _collect_issues(analyzer, analyzer_name, data)
    typed_status = _status_from(data, status, error)
    if typed_status == AnalyzerStatus.COMPLETED and warnings:
        typed_status = AnalyzerStatus.COMPLETED_WITH_WARNINGS
    analyzer_id = analyzer_name
    if error and not errors:
        errors = [
            _execution_error(
                analyzer_id,
                typed_status,
                error,
                recoverable=typed_status in _RECOVERABLE_STATUSES,
            )
        ]
    data = _typed_result(analyzer_id, data, status=typed_status.value, error=error)
    _results_bucket(context)[result_key] = data
    structured_errors, structured_warnings = _structured_issues(analyzer_id, data)
    errors = [*errors, *structured_errors]
    warnings = [*warnings, *structured_warnings]
    version, output_schema = _execution_identity(stage, analyzer_name)
    raw_duration = data.get("execution_time") if isinstance(data, dict) else None
    execution: AnalyzerExecution[Any] = AnalyzerExecution(
        analyzer_id=analyzer_id,
        analyzer_version=version,
        output_schema=output_schema,
        status=typed_status,
        data=data,
        errors=errors,
        warnings=warnings,
        duration=(
            float(raw_duration)
            if isinstance(raw_duration, (int, float)) and not isinstance(raw_duration, bool)
            else time.monotonic() - started
        ),
        metrics=dict(data.metrics) if isinstance(data, TypedAnalyzerResult) else {},
    )
    _record_analyzer_execution(context, execution)
    if error or typed_status != AnalyzerStatus.COMPLETED:
        _record_analyzer_status(context, analyzer_id, status=typed_status.value, error=error)
    return {result_key: data}


def _store_failure(
    stage: Any,
    context: dict[str, Any],
    analyzer_name: str,
    result_key: str,
    error_default: Callable[[Exception], Any],
    exc: Exception,
    started: float,
) -> dict[str, Any]:
    fallback = _typed_result(analyzer_name, error_default(exc), status="failed", error=str(exc))
    _results_bucket(context)[result_key] = fallback
    record_analyzer_execution(
        stage,
        context,
        analyzer_name,
        fallback,
        status=AnalyzerStatus.FAILED,
        error=str(exc),
        duration=time.monotonic() - started,
    )
    return {result_key: fallback}


def run_registered_analyzer(
    stage: Any,
    context: dict[str, Any],
    analyzer_name: str,
    result_key: str,
    *,
    invoke: Callable[[Any], Any],
    error_default: Callable[[Exception], Any],
    log_label: str,
) -> dict[str, Any] | None:
    """Run one registered analyzer and always record its execution envelope."""
    analyzer_class = stage.registry.get_analyzer_class(analyzer_name)
    if not analyzer_class:
        record_skipped_execution(
            stage,
            context,
            analyzer_name,
            AnalyzerStatus.DEPENDENCY_UNAVAILABLE,
            "analyzer is not registered",
        )
        return None
    started = time.monotonic()
    try:
        analyzer = stage.analyzer_factory(
            analyzer_class,
            adapter=stage.adapter,
            config=stage.config,
            filename=stage.filename,
        )
        return _store_success(
            stage, context, analyzer_name, result_key, invoke(analyzer), analyzer, started
        )
    except Exception as exc:
        logger.warning("%s failed: %s", log_label, exc)
        return _store_failure(
            stage, context, analyzer_name, result_key, error_default, exc, started
        )


__all__ = [
    "_record_analyzer_execution",
    "_typed_result",
    "record_analyzer_execution",
    "record_skipped_execution",
    "run_registered_analyzer",
]
