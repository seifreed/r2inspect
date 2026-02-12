#!/usr/bin/env python3
"""Use case for running a complete binary analysis."""

from __future__ import annotations

from typing import Any

from ..analysis_service import AnalysisService, default_analysis_service


class AnalyzeBinaryUseCase:
    """Orchestrate analysis execution and statistics enrichment."""

    def __init__(self, analysis_service: AnalysisService | None = None) -> None:
        self._analysis_service = analysis_service or default_analysis_service

    def run(
        self,
        inspector: Any,
        options: dict[str, Any],
        *,
        reset_stats: bool = True,
        include_statistics: bool = True,
        validate_schemas: bool = True,
    ) -> dict[str, Any]:
        if reset_stats:
            self._analysis_service.reset_stats()
        results = self._analysis_service.execute(inspector, options)
        if include_statistics:
            self._analysis_service.add_statistics(results)
        if validate_schemas:
            self._analysis_service.validate_results(results)
        return results
