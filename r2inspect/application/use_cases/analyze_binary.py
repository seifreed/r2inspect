#!/usr/bin/env python3
"""Use case for running a complete binary analysis."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import TYPE_CHECKING, Any
import uuid

from ...infrastructure.logging import bind_log_context, current_log_context, get_logger
from ..result_mapper import build_analysis_result
from ..analysis_service import AnalysisService, default_analysis_service

logger = get_logger(__name__)

if TYPE_CHECKING:
    from ...interfaces import BinaryInspector
    from ...schemas.results_models import AnalysisResult


@dataclass(frozen=True)
class AnalyzeBinaryRequest:
    """Input model for binary analysis execution.

    Attributes:
        inspector: The selected binary inspector implementation.
        options: Analysis options (e.g. detect_packer, custom_yara).
        reset_stats: Whether to reset service statistics before analysis.
        include_statistics: Whether to enrich results with execution stats.
        validate_schemas: Whether to validate output against Pydantic schemas.
    """

    inspector: BinaryInspector
    options: dict[str, Any]
    reset_stats: bool = True
    include_statistics: bool = True
    validate_schemas: bool = True


class AnalyzeBinaryUseCase:
    """Orchestrate analysis execution and statistics enrichment."""

    def __init__(self, analysis_service: AnalysisService | None = None) -> None:
        self._analysis_service = analysis_service or default_analysis_service

    def execute(self, request: AnalyzeBinaryRequest) -> AnalysisResult:
        correlation_id = current_log_context().get("correlation_id") or uuid.uuid4().hex
        started = time.perf_counter()
        with bind_log_context(correlation_id=correlation_id, operation="analyze_binary"):
            logger.debug(
                "Binary analysis started",
                extra={"event_name": "analysis.started", "profile": request.options.get("profile")},
            )
            try:
                if request.reset_stats:
                    self._analysis_service.reset_stats()
                results = self._analysis_service.execute(request.inspector, request.options)
                if request.include_statistics:
                    self._analysis_service.add_statistics(results)
                if request.validate_schemas:
                    self._analysis_service.validate_results(results)
                result = build_analysis_result(results)
            except Exception:
                logger.exception(
                    "Binary analysis failed",
                    extra={
                        "event_name": "analysis.failed",
                        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                        "outcome": "failed",
                    },
                )
                raise
            logger.info(
                "Binary analysis completed",
                extra={
                    "event_name": "analysis.completed",
                    "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                    "outcome": "success",
                },
            )
            return result

    def run(
        self,
        inspector: BinaryInspector,
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
