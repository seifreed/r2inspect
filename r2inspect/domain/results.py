"""Typed result models for analysis outputs."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class AnalyzerResult:
    """Base result model for analyzer outputs."""

    available: bool = False
    error: str | None = None
    execution_time: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HashResult(AnalyzerResult):
    """Result model for hashing analyzers."""

    hash_type: str = ""
    hash_value: str | None = None
    file_size: int = 0
    method_used: str | None = None
