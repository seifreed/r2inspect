#!/usr/bin/env python3
"""Result aggregation facade."""

from typing import Any

from ..infrastructure.logging import get_logger
from .result_aggregator_support import (
    INDICATOR_RULES,
    build_file_overview as _build_file_overview,
    build_security_assessment as _build_security_assessment,
    build_technical_details as _build_technical_details,
    build_threat_indicators as _build_threat_indicators,
    count_crypto_indicators as _count_crypto_indicators,
    count_high_entropy_sections as _count_high_entropy_sections,
    count_suspicious_imports as _count_suspicious_imports,
    count_suspicious_sections as _count_suspicious_sections,
    generate_executive_summary as _generate_executive_summary_impl,
    generate_indicators as _generate_indicators_impl,
    generate_recommendations as _generate_recommendations,
    get_summary_builders as _get_summary_builders,
    normalize_results as _normalize_results,
)

logger = get_logger(__name__)


class ResultAggregator:
    """Facade for indicator and executive-summary generation."""

    def generate_indicators(self, analysis_results: dict[str, Any]) -> list[dict[str, Any]]:
        """Generate suspicious indicators from normalized analysis results."""
        return _generate_indicators_impl(_normalize_results(analysis_results), INDICATOR_RULES)

    def generate_executive_summary(self, analysis_results: dict[str, Any]) -> dict[str, Any]:
        """Generate the executive summary from normalized analysis results."""
        try:
            return _generate_executive_summary_impl(
                _normalize_results(analysis_results), _get_summary_builders()
            )
        except Exception as exc:
            logger.error("Error generating executive summary: %s", exc)
            return {"error": str(exc)}


__all__ = [
    "ResultAggregator",
    "_build_file_overview",
    "_build_security_assessment",
    "_build_technical_details",
    "_build_threat_indicators",
    "_count_crypto_indicators",
    "_count_high_entropy_sections",
    "_count_suspicious_imports",
    "_count_suspicious_sections",
    "_generate_recommendations",
    "_normalize_results",
]
