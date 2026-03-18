#!/usr/bin/env python3
"""Runtime-oriented ports shared across layers."""

from __future__ import annotations

from typing import Any, Protocol

from ..domain.analysis_runtime import AnalysisRuntimeStats


class AnalysisRuntimePort(Protocol):
    """Port for runtime statistics and lifecycle hooks."""

    def reset(self) -> None: ...

    def collect(self) -> AnalysisRuntimeStats: ...


class ResultValidationPort(Protocol):
    """Port for optional result validation."""

    def validate(self, results: dict[str, Any], *, enabled: bool) -> None: ...
