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


def _accumulate_function_stats(functions: list[Any]) -> tuple[int, int, list[int]]:
    with_size = 0
    with_blocks = 0
    sizes: list[int] = []
    for func in functions:
        if not isinstance(func, dict):
            continue
        size = coerce_positive_int(func.get("size"))
        if size > 0:
            with_size += 1
            sizes.append(size)
        if coerce_positive_int(func.get("nbbs")) > 0:
            with_blocks += 1
    return with_size, with_blocks, sizes


def analyze_function_coverage(functions: Any) -> dict[str, Any]:
    try:
        if not isinstance(functions, list):
            return {}
        total = len(functions)
        with_size, with_blocks, sizes = _accumulate_function_stats(functions)
        coverage: dict[str, Any] = {
            "total_functions": total,
            "functions_with_size": with_size,
            "functions_with_blocks": with_blocks,
            "total_code_coverage": sum(sizes) if sizes else 0,
            "avg_function_size": (sum(sizes) / len(sizes)) if sizes else 0,
        }
        if total > 0:
            coverage["size_coverage_percent"] = with_size / total * 100
            coverage["block_coverage_percent"] = with_blocks / total * 100
        return coverage
    except (TypeError, ValueError, AttributeError):
        return {}
