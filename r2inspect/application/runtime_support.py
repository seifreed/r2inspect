#!/usr/bin/env python3
"""Application runtime support implementations."""

from __future__ import annotations

import os

from ..error_handling.classifier import reset_error_stats
from ..error_handling.stats import (
    get_circuit_breaker_stats,
    get_error_stats,
    get_retry_stats,
)
from ..interfaces import AnalysisRuntimePort, ResultValidationPort
from ..domain.analysis_runtime import AnalysisRuntimeStats
from ..schemas import ResultConverter


class DefaultAnalysisRuntime(AnalysisRuntimePort):
    """Bridge runtime statistics from existing global collectors."""

    def reset(self) -> None:
        reset_error_stats()

    def collect(self) -> AnalysisRuntimeStats:
        return AnalysisRuntimeStats(
            error_stats=get_error_stats(),
            retry_stats=get_retry_stats(),
            circuit_breaker_stats=get_circuit_breaker_stats(),
        )


class SchemaResultValidator(ResultValidationPort):
    """Validate analyzer payloads against registered schemas when enabled."""

    def validate(self, results: dict[str, object], *, enabled: bool) -> None:
        if not enabled:
            return
        registered = ResultConverter.list_registered_schemas()
        for analyzer_name in registered:
            payload = results.get(analyzer_name)
            if isinstance(payload, dict):
                ResultConverter.convert_result(analyzer_name, payload, strict=False)


def schema_validation_enabled() -> bool:
    """Read schema validation toggle from environment at runtime."""
    flag = os.getenv("R2INSPECT_VALIDATE_SCHEMAS", "").strip().lower()
    return flag in {"1", "true", "yes"}


def create_default_analysis_runtime() -> AnalysisRuntimePort:
    """Create the default runtime statistics bridge."""
    return DefaultAnalysisRuntime()


def create_default_result_validator() -> ResultValidationPort:
    """Create the default schema result validator."""
    return SchemaResultValidator()
