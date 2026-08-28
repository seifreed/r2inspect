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
    ) -> None:
        super().__init__(payload)
        self.analyzer_id = analyzer_id
        self.status = status
        self.error = error

    def to_dict(self) -> dict[str, object]:
        """Return the payload while retaining legacy mapping behavior."""
        return dict(self)


T = TypeVar("T")


def typed_analyzer_entrypoint(method: Callable[..., T]) -> Callable[..., T | TypedAnalyzerResult]:
    """Wrap mapping payloads returned by public analyzer entrypoints."""
    if getattr(method, "_typed_result_wrapper", False):
        return method

    @wraps(method)
    def wrapped(analyzer: Any, *args: Any, **kwargs: Any) -> T | TypedAnalyzerResult:
        value = method(analyzer, *args, **kwargs)
        if isinstance(value, TypedAnalyzerResult) or not isinstance(value, dict):
            return value
        get_name = getattr(analyzer, "get_name", None)
        analyzer_id = get_name() if callable(get_name) else analyzer.__class__.__name__
        last_error = getattr(analyzer, "last_error", None)
        return TypedAnalyzerResult(
            value,
            analyzer_id=str(analyzer_id),
            status=str(getattr(analyzer, "last_status", None) or "completed"),
            error=str(last_error) if last_error else None,
        )

    wrapped._typed_result_wrapper = True  # type: ignore[attr-defined]
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
