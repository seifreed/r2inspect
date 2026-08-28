"""Typed result models for analysis outputs."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from functools import wraps
from typing import Any, TypeVar

from .entities import _ToDictMixin


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


T = TypeVar("T")


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
                status=str(getattr(analyzer, "last_status", None) or "completed"),
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
