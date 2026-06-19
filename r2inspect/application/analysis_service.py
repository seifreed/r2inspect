#!/usr/bin/env python3
"""Application service for analysis execution and statistics."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from ..interfaces import AnalysisRuntimePort, ResultValidationPort
from ..infrastructure.proxying import LazyProxy
from .runtime_support import (
    create_default_analysis_runtime,
    create_default_result_validator,
    schema_validation_enabled,
)


def _is_active_metric(value: Any) -> bool:
    if isinstance(value, int | float):
        return value > 0
    if isinstance(value, str):
        return value.lower() != "closed"
    return False


def _circuit_value_is_active(value: Any) -> bool:
    if isinstance(value, int | float):
        return value > 0
    if isinstance(value, dict):
        return any(_is_active_metric(nested) for nested in value.values())
    return False


class AnalysisService:
    """Encapsulates analysis execution and statistics enrichment."""

    def __init__(
        self,
        runtime: AnalysisRuntimePort | None = None,
        result_validator: ResultValidationPort | None = None,
        validation_enabled: Callable[[], bool] | None = None,
    ) -> None:
        self._runtime = runtime or create_default_analysis_runtime()
        self._result_validator = result_validator or create_default_result_validator()
        self._validation_enabled = validation_enabled or schema_validation_enabled

    def reset_stats(self) -> None:
        self._runtime.reset()

    def execute(self, inspector: Any, options: dict[str, Any]) -> dict[str, Any]:
        return cast(dict[str, Any], inspector.analyze(**options))

    def add_statistics(self, results: dict[str, Any]) -> None:
        runtime_stats = self._runtime.collect()
        error_stats = runtime_stats.error_stats
        retry_stats = runtime_stats.retry_stats
        circuit_stats = runtime_stats.circuit_breaker_stats

        if error_stats["total_errors"] > 0:
            results["error_statistics"] = error_stats

        if retry_stats.get("total_retries", 0) > 0:
            results["retry_statistics"] = retry_stats

        if self.has_circuit_breaker_data(circuit_stats):
            results["circuit_breaker_statistics"] = circuit_stats

    def validate_results(self, results: dict[str, Any]) -> None:
        self._result_validator.validate(results, enabled=self._validation_enabled())

    @staticmethod
    def has_circuit_breaker_data(circuit_stats: dict[str, Any]) -> bool:
        if not circuit_stats:
            return False
        return any(_circuit_value_is_active(value) for value in circuit_stats.values())

    @staticmethod
    def _should_validate_schemas() -> bool:
        return schema_validation_enabled()


_default_analysis_service: AnalysisService | None = None


def get_default_analysis_service() -> AnalysisService:
    """Return the lazily-created default AnalysisService singleton."""
    global _default_analysis_service
    if _default_analysis_service is None:
        _default_analysis_service = AnalysisService()
    return _default_analysis_service


default_analysis_service: AnalysisService = cast(
    AnalysisService, LazyProxy(get_default_analysis_service)
)
