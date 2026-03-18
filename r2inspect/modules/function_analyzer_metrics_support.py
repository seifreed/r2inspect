"""Statistics and coverage helpers for function analysis."""

from __future__ import annotations

from typing import Any

from ..domain.services.function_analysis import build_function_stats
from .function_analyzer_extraction_support import coerce_positive_int


def generate_function_stats(functions: list[dict[str, Any]], logger: Any) -> dict[str, Any]:
    try:
        return build_function_stats(functions)
    except Exception as exc:
        logger.error("Error generating function stats: %s", str(exc))
        return {"error": f"Stats generation failed: {str(exc)}"}


def calculate_std_dev(values: list[float]) -> float:
    try:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance: float = sum((x - mean) ** 2 for x in values) / len(values)
        return float(variance**0.5)
    except (TypeError, ValueError):
        return 0.0


def analyze_function_coverage(functions: Any) -> dict[str, Any]:
    try:
        if not isinstance(functions, list):
            return {}
        coverage: dict[str, Any] = {
            "total_functions": len(functions),
            "functions_with_size": 0,
            "functions_with_blocks": 0,
            "total_code_coverage": 0,
            "avg_function_size": 0,
        }
        sizes = []
        for func in functions:
            if not isinstance(func, dict):
                continue
            size = coerce_positive_int(func.get("size"))
            if size > 0:
                coverage["functions_with_size"] += 1
                sizes.append(size)
            if coerce_positive_int(func.get("nbbs")) > 0:
                coverage["functions_with_blocks"] += 1
        if sizes:
            coverage["total_code_coverage"] = sum(sizes)
            coverage["avg_function_size"] = sum(sizes) / len(sizes)
        if coverage["total_functions"] > 0:
            coverage["size_coverage_percent"] = (
                coverage["functions_with_size"] / coverage["total_functions"]
            ) * 100
            coverage["block_coverage_percent"] = (
                coverage["functions_with_blocks"] / coverage["total_functions"]
            ) * 100
        return coverage
    except (TypeError, ValueError, AttributeError):
        return {}
