#!/usr/bin/env python3
"""Use case for running a complete binary analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..result_mapper import build_analysis_result
from ..analysis_service import AnalysisService, default_analysis_service

if TYPE_CHECKING:
    from ...core.inspector import R2Inspector
    from ...schemas.results_models import AnalysisResult


@dataclass(frozen=True)
class AnalyzeBinaryRequest:
    """Input model for binary analysis execution."""

    inspector: R2Inspector
    options: dict[str, Any]
    reset_stats: bool = True
    include_statistics: bool = True
    validate_schemas: bool = True


class AnalyzeBinaryUseCase:
    """Orchestrate analysis execution and statistics enrichment."""

    def __init__(self, analysis_service: AnalysisService | None = None) -> None:
        self._analysis_service = analysis_service or default_analysis_service

    def execute(self, request: AnalyzeBinaryRequest) -> AnalysisResult:
        if request.reset_stats:
            self._analysis_service.reset_stats()
        results = self._analysis_service.execute(request.inspector, request.options)
        if request.include_statistics:
            self._analysis_service.add_statistics(results)
        if request.validate_schemas:
            self._analysis_service.validate_results(results)
        return build_analysis_result(results)

    def run(
        self,
        inspector: R2Inspector,
        options: dict[str, Any],
        *,
        reset_stats: bool = True,
        include_statistics: bool = True,
        validate_schemas: bool = True,
    ) -> AnalysisResult:
        return self.execute(
            AnalyzeBinaryRequest(
                inspector=inspector,
                options=options,
                reset_stats=reset_stats,
                include_statistics=include_statistics,
                validate_schemas=validate_schemas,
            )
        )
