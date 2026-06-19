"""Shared helper operations for import analysis.

Pure functions are re-exported from domain.analysis.import_risk.
Infrastructure-dependent functions remain here.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Protocol

from ..domain.analysis.import_risk import (
    count_suspicious_indicators,
    get_function_description,
    get_risk_level,
    is_candidate_api_string,
    matches_known_api,
)


class ImportHost(Protocol):
    """Overridable collaboration contract the import-analysis helper depends on."""

    api_categories: dict[str, Any]

    def _calculate_risk_score(self, func_name: str) -> dict[str, Any]: ...
    def _get_function_description(self, func_name: str) -> str: ...


__all__ = [
    "get_risk_level",
    "count_suspicious_indicators",
    "analyze_import",
    "get_function_description",
    "is_candidate_api_string",
    "matches_known_api",
    "check_import_forwarding",
]


def _to_int(value: Any) -> int:
    try:
        if isinstance(value, str):
            return int(value, 0)
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def analyze_import(
    imp: dict[str, Any], analyzer: ImportHost, *, logger: logging.Logger
) -> dict[str, Any]:
    if not isinstance(imp, dict):
        imp = {}
    name_value = imp.get("name")
    name = name_value if isinstance(name_value, str) else "unknown"
    analysis = {
        "name": name,
        "address": hex(_to_int(imp.get("plt", 0))),
        "ordinal": imp.get("ordinal", 0),
        "library": imp.get("libname") or imp.get("library", "unknown"),
        "type": imp.get("type", "unknown"),
        "category": "Unknown",
        "risk_score": 0,
        "risk_level": "Low",
        "risk_tags": [],
        "description": "",
    }
    try:
        risk_analysis = analyzer._calculate_risk_score(name)
        if isinstance(risk_analysis, dict):
            analysis.update(risk_analysis)
        api_categories = analyzer.api_categories
        if not isinstance(api_categories, dict):
            api_categories = {}
        for category, functions in api_categories.items():
            if not isinstance(functions, (list, tuple, set)):
                continue
            if any(isinstance(api, str) and api in name for api in functions):
                analysis["category"] = category
                analysis["description"] = analyzer._get_function_description(name)
                break
    except Exception as exc:
        logger.error(
            "Error analyzing import %s from %s: %s",
            analysis["name"],
            analysis["library"],
            exc,
        )
        analysis["error"] = str(exc)
    return analysis


def check_import_forwarding(strings: list[Any], *, logger: logging.Logger) -> dict[str, Any]:
    try:
        if not strings:
            return {"detected": False, "forwards": [], "count": 0}
        forwards = []
        for string_entry in strings:
            if isinstance(string_entry, dict) and "string" in string_entry:
                string_value = string_entry["string"]
                if not isinstance(string_value, str):
                    continue
                if re.match(r"^\w+\.(?:\w+|#\d+)$", string_value):
                    forwards.append(
                        {
                            "forward": string_value,
                            "address": string_entry.get("vaddr", 0),
                        }
                    )
        return {
            "detected": len(forwards) > 0,
            "forwards": forwards,
            "count": len(forwards),
        }
    except (RuntimeError, TypeError, ValueError, AttributeError) as exc:
        logger.error("Error checking import forwarding: %s", exc)
        return {"detected": False, "forwards": [], "count": 0}
