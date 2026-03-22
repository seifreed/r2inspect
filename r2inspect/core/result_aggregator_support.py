#!/usr/bin/env python3
"""Support functions and rules for result aggregation."""

from __future__ import annotations

from typing import Any

from .result_aggregator_indicator_support import (
    generate_indicators,
    indicator_rules,
)
from .result_aggregator_summary_support import (
    _count_crypto_indicators as _count_crypto_indicators_impl,
    _count_high_entropy_sections as _count_high_entropy_sections_impl,
    _count_suspicious_imports as _count_suspicious_imports_impl,
    _count_suspicious_sections as _count_suspicious_sections_impl,
    build_file_overview,
    build_security_assessment,
    build_technical_details,
    build_threat_indicators,
    generate_executive_summary,
    generate_recommendations,
    summary_builders,
)

DEFAULTS: dict[str, Any] = {
    "file_info": {},
    "pe_info": {},
    "security": {},
    "packer": {},
    "anti_analysis": {},
    "imports": [],
    "yara_matches": [],
    "sections": [],
    "functions": {},
    "crypto": {},
    "rich_header": {},
}


def normalize_results(analysis_results: dict[str, Any]) -> dict[str, Any]:
    """Populate missing top-level result buckets with safe defaults."""
    return {
        key: default if (val := analysis_results.get(key, default)) is None else val
        for key, default in DEFAULTS.items()
    }


def count_suspicious_imports(imports: list[dict[str, Any]]) -> int:
    """Proxy the executive-summary suspicious import count logic."""
    return _count_suspicious_imports_impl(imports)


def count_high_entropy_sections(sections: list[dict[str, Any]]) -> int:
    """Proxy the executive-summary high-entropy section count logic."""
    return _count_high_entropy_sections_impl(sections)


def count_suspicious_sections(sections: list[dict[str, Any]]) -> int:
    """Proxy the executive-summary suspicious section count logic."""
    return _count_suspicious_sections_impl(sections)


def count_crypto_indicators(crypto: dict[str, Any]) -> int:
    """Proxy the executive-summary crypto-indicator count logic."""
    return _count_crypto_indicators_impl(crypto)


INDICATOR_RULES = indicator_rules()
SUMMARY_BUILDERS = summary_builders


def get_summary_builders() -> dict[str, Any]:
    """Return the canonical executive-summary builder mapping."""
    return SUMMARY_BUILDERS()
