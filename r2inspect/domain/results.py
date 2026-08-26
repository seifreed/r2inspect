"""Typed result models for analysis outputs."""

from __future__ import annotations

from dataclasses import dataclass

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
