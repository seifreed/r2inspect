"""Shared helper operations for section analysis."""

from __future__ import annotations

from typing import Any

from ..domain.services.section_analysis import build_section_characteristics


def analyze_single_section(
    analyzer: Any, section: dict[str, Any], *, logger: Any
) -> dict[str, Any]:
    analysis = {
        "name": str(section.get("name", "unknown")),
        "virtual_address": section.get("vaddr", 0),
        "virtual_size": section.get("vsize", 0),
        "raw_size": section.get("size", 0),
        "flags": section.get("flags", ""),
        "entropy": 0.0,
        "is_executable": False,
        "is_writable": False,
        "is_readable": False,
        "suspicious_indicators": [],
        "characteristics": {},
        "pe_characteristics": [],
        "size_ratio": 0.0,
    }
    try:
        analyzer._apply_permissions(section, analysis)
        analyzer._apply_pe_characteristics(section, analysis)
        analysis["size_ratio"] = analyzer._calculate_size_ratio(analysis)
        analysis["entropy"] = analyzer._calculate_entropy(section)
        analysis["suspicious_indicators"] = analyzer._check_suspicious_characteristics(
            section, analysis
        )
        analysis["characteristics"] = analyzer._get_section_characteristics(section, analysis)
    except Exception as exc:
        logger.error("Error in single section analysis: %s", exc)
        analysis["error"] = str(exc)
    return analysis


def get_section_characteristics(
    analyzer: Any, section: dict[str, Any], analysis: dict[str, Any], *, logger: Any
) -> dict[str, Any]:
    try:
        name = str(section.get("name", ""))
        code_analysis = (
            analyzer._analyze_code_section(section) if analysis.get("is_executable") else None
        )
        return build_section_characteristics(name, analysis, code_analysis)
    except Exception as exc:
        logger.error("Error getting section characteristics: %s", exc)
        return {}


def analyze_code_section(analyzer: Any, section: dict[str, Any], *, logger: Any) -> dict[str, Any]:
    code_info: dict[str, Any] = {}
    try:
        vaddr = section.get("vaddr", 0)
        size = section.get("size", 0)
        if size == 0:
            return code_info
        functions = analyzer._get_functions_in_section(vaddr, size)
        code_info["function_count"] = len(functions)
        if functions:
            sizes = [
                f.get("size", 0) for f in functions if isinstance(f, dict) and f.get("size", 0) > 0
            ]
            if sizes:
                code_info["avg_function_size"] = sum(sizes) / len(sizes)
                code_info["min_function_size"] = min(sizes)
                code_info["max_function_size"] = max(sizes)
        nop_count, sample_size = analyzer._count_nops_in_section(vaddr, size)
        if sample_size > 0:
            code_info["nop_sample_size"] = sample_size
            code_info["nop_count"] = nop_count
            code_info["nop_ratio"] = nop_count / sample_size
            if nop_count > sample_size / 100:
                code_info["excessive_nops"] = True
    except Exception as exc:
        logger.error("Error analyzing code section: %s", exc)
    return code_info
