#!/usr/bin/env python3
"""Application service for analysis execution and statistics."""

from __future__ import annotations

from typing import Any, cast

from ..error_handling.stats import (
    get_circuit_breaker_stats,
    get_error_stats,
    get_retry_stats,
    reset_error_stats,
)


class AnalysisService:
    """Encapsulates analysis execution and statistics enrichment."""

    def reset_stats(self) -> None:
        reset_error_stats()

    def execute(self, inspector: Any, options: dict[str, Any]) -> dict[str, Any]:
        return cast(dict[str, Any], inspector.analyze(**options))

    def add_statistics(self, results: dict[str, Any]) -> None:
        error_stats = get_error_stats()
        retry_stats = get_retry_stats()
        circuit_stats = get_circuit_breaker_stats()

        if error_stats["total_errors"] > 0:
            results["error_statistics"] = error_stats

        if retry_stats.get("total_retries", 0) > 0:
            results["retry_statistics"] = retry_stats

        if self.has_circuit_breaker_data(circuit_stats):
            results["circuit_breaker_statistics"] = circuit_stats

    @staticmethod
    def has_circuit_breaker_data(circuit_stats: dict[str, Any]) -> bool:
        if not circuit_stats:
            return False

        for _, value in circuit_stats.items():
            if isinstance(value, int | float) and value > 0:
                return True
            if isinstance(value, dict):
                for nested in value.values():
                    if isinstance(nested, int | float) and nested > 0:
                        return True
                    if isinstance(nested, str) and nested.lower() != "closed":
                        return True
        return False


default_analysis_service = AnalysisService()
