"""Shared helper operations for import analysis.

Pure functions are re-exported from domain.analysis.import_risk.
Infrastructure-dependent functions remain here.
"""

from __future__ import annotations

import re
from typing import Any

from ..domain.analysis.import_risk import (
    count_suspicious_indicators,
    get_function_description,
    get_risk_level,
    is_candidate_api_string,
    matches_known_api,
)

__all__ = [
    "get_risk_level",
    "count_suspicious_indicators",
    "analyze_import",
    "get_function_description",
    "is_candidate_api_string",
    "matches_known_api",
    "check_import_forwarding",
]


def analyze_import(imp: dict[str, Any], analyzer: Any, *, logger: Any) -> dict[str, Any]:
    analysis = {
        "name": imp.get("name", "unknown"),
        "address": hex(imp.get("plt", 0)),
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
        func_name = imp.get("name", "")
        risk_analysis = analyzer._calculate_risk_score(func_name)
        analysis.update(risk_analysis)
        for category, functions in analyzer.api_categories.items():
            if any(api in func_name for api in functions):
                analysis["category"] = category
                analysis["description"] = analyzer._get_function_description(func_name)
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


def check_import_forwarding(strings: list[Any], *, logger: Any) -> dict[str, Any]:
    try:
        if not strings:
            return {"detected": False, "forwards": []}
        forwards = []
        for string_entry in strings:
            if isinstance(string_entry, dict) and "string" in string_entry:
                string_value = string_entry["string"]
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
        return {"detected": False, "forwards": []}
