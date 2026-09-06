"""Typed result models for analysis outputs."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from functools import wraps
from typing import Any, ClassVar, Generic, TypeVar

from .entities import _ToDictMixin

T = TypeVar("T")


class AnalyzerStatus(StrEnum):
    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    PARTIAL = "partial"
    NOT_DETECTED = "not_detected"
    NOT_APPLICABLE = "not_applicable"
    UNSUPPORTED = "unsupported"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    SKIPPED_BY_PROFILE = "skipped_by_profile"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


def analyzer_status_from_payload(value: Any, explicit: Any = None) -> AnalyzerStatus:
    """Resolve status from structured fields only; human messages are never parsed."""
    if explicit is not None:
        try:
            return AnalyzerStatus(str(explicit))
        except ValueError:
            return AnalyzerStatus.FAILED
    if isinstance(value, dict):
        payload_status = value.get("status")
        if payload_status:
            try:
                return AnalyzerStatus(str(payload_status))
            except ValueError:
                return AnalyzerStatus.FAILED
        if value.get("library_available") is False:
            return AnalyzerStatus.DEPENDENCY_UNAVAILABLE
        if value.get("available") is False:
            return AnalyzerStatus.FAILED
        if value.get("detected") is False:
            return AnalyzerStatus.NOT_DETECTED
    return AnalyzerStatus.COMPLETED


@dataclass(frozen=True)
class AnalyzerError:
    code: str
    component: str
    message: str
    recoverable: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "component": self.component,
            "message": self.message,
            "recoverable": self.recoverable,
        }


@dataclass(frozen=True)
class AnalyzerWarning:
    code: str
    component: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "component": self.component, "message": self.message}


@dataclass
class AnalyzerExecution(Generic[T]):
    """Analyzer payload plus explicit execution metadata, independent of data shape."""

    analyzer_id: str
    analyzer_version: str = "unknown"
    output_schema: str | None = None
    status: AnalyzerStatus = AnalyzerStatus.COMPLETED
    data: T | None = None
    errors: list[AnalyzerError] = field(default_factory=list)
    warnings: list[AnalyzerWarning] = field(default_factory=list)
    duration: float = 0.0
    metrics: dict[str, Any] = field(default_factory=dict)

    schema_version: ClassVar[str] = "r2inspect.analyzer/v1"

    def __post_init__(self) -> None:
        self.status = AnalyzerStatus(self.status)
        self.errors = list(self.errors or [])
        self.warnings = list(self.warnings or [])
        self.metrics = dict(self.metrics or {})

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "analyzer_id": self.analyzer_id,
            "analyzer_version": self.analyzer_version,
            "output_schema": self.output_schema,
            "status": self.status.value,
            "data": self.data,
            "errors": [error.to_dict() for error in self.errors],
            "warnings": [warning.to_dict() for warning in self.warnings],
            "duration": self.duration,
            "metrics": self.metrics,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> AnalyzerExecution[Any]:
        return cls(
            analyzer_id=str(value["analyzer_id"]),
            analyzer_version=str(value.get("analyzer_version") or "unknown"),
            output_schema=(str(value["output_schema"]) if value.get("output_schema") else None),
            status=AnalyzerStatus(str(value.get("status", "completed"))),
            data=value.get("data"),
            errors=[AnalyzerError(**item) for item in value.get("errors", [])],
            warnings=[AnalyzerWarning(**item) for item in value.get("warnings", [])],
            duration=float(value.get("duration", 0.0)),
            metrics=dict(value.get("metrics", {})),
        )


class TypedAnalyzerResult(dict[str, object]):
    """Mapping-compatible analyzer payload with explicit execution metadata."""

    schema_version = "r2inspect.analyzer/v1"

    def __init__(
        self,
        payload: dict[str, object],
        *,
        analyzer_id: str,
        status: str = "completed",
        error: str | None = None,
        metrics: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(payload)
        self.analyzer_id = analyzer_id
        self.status = status
        self.error = error
        self.metrics = dict(metrics or {})

    def to_dict(self) -> dict[str, object]:
        """Return the payload while retaining legacy mapping behavior."""
        return dict(self)


def _process_memory_mb() -> float | None:
    """Read process RSS without making optional measurement support mandatory."""
    try:
        import os

        import psutil

        return float(psutil.Process(os.getpid()).memory_info().rss) / 1024 / 1024
    except Exception:
        return None


def typed_analyzer_entrypoint(method: Callable[..., T]) -> Callable[..., T | TypedAnalyzerResult]:
    """Wrap mapping payloads returned by public analyzer entrypoints."""
    if getattr(method, "_typed_result_wrapper", False):
        return method

    @wraps(method)
    def wrapped(analyzer: Any, *args: Any, **kwargs: Any) -> T | TypedAnalyzerResult:
        memory_before = _process_memory_mb()
        value = method(analyzer, *args, **kwargs)
        memory_after = _process_memory_mb()
        typed: TypedAnalyzerResult
        if isinstance(value, TypedAnalyzerResult):
            typed = value
        elif not isinstance(value, dict):
            return value
        else:
            get_name = getattr(analyzer, "get_name", None)
            analyzer_id = get_name() if callable(get_name) else analyzer.__class__.__name__
            last_error = getattr(analyzer, "last_error", None)
            typed = TypedAnalyzerResult(
                value,
                analyzer_id=str(analyzer_id),
                status=analyzer_status_from_payload(
                    value, getattr(analyzer, "last_status", None)
                ).value,
                error=str(last_error) if last_error else None,
            )
        if memory_before is not None and memory_after is not None:
            typed.metrics.update(
                {
                    "process_memory_before_mb": memory_before,
                    "process_memory_after_mb": memory_after,
                    "memory_delta_mb": memory_after - memory_before,
                }
            )
        return typed

    wrapped.__dict__["_typed_result_wrapper"] = True
    return wrapped


@dataclass
class AnalyzerResult(_ToDictMixin):
    """Base result model for analyzer outputs."""

    available: bool = False
    error: str | None = None
    execution_time: float = 0.0


@dataclass
class HashResult(AnalyzerResult):
    """Result model for hashing analyzers."""

    hash_type: str = ""
    hash_value: str | None = None
    file_size: int = 0
    method_used: str | None = None
