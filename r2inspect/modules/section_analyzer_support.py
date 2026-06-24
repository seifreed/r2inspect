"""Shared helper operations for section analysis."""

from __future__ import annotations

import logging
from typing import Any, Protocol

from ..abstractions.coercion_support import coerce_int
from ..domain.services.section_analysis import build_section_characteristics


class SectionHost(Protocol):
    """Overridable collaboration contract the section-analysis helpers depend on."""

    def _apply_permissions(self, section: dict[str, Any], analysis: dict[str, Any]) -> None: ...
    def _apply_pe_characteristics(
        self, section: dict[str, Any], analysis: dict[str, Any]
    ) -> None: ...
    def _calculate_size_ratio(self, analysis: dict[str, Any]) -> float: ...
    def _calculate_entropy(self, section: dict[str, Any]) -> float: ...
    def _check_suspicious_characteristics(
        self, section: dict[str, Any], analysis: dict[str, Any]
    ) -> list[str]: ...
    def _get_section_characteristics(
        self, section: dict[str, Any], analysis: dict[str, Any]
    ) -> dict[str, Any]: ...
    def _analyze_code_section(self, section: dict[str, Any]) -> dict[str, Any]: ...
    def _get_functions_in_section(self, vaddr: int, size: int) -> list[dict[str, Any]]: ...
    def _count_nops_in_section(self, vaddr: int, size: int) -> tuple[int, int]: ...


def analyze_single_section(
    analyzer: SectionHost, section: dict[str, Any], *, logger: logging.Logger
) -> dict[str, Any]:
    analysis = {
        "name": str(section.get("name", "unknown")),
        "virtual_address": coerce_int(section.get("vaddr", 0)),
        "virtual_size": coerce_int(section.get("vsize", 0)),
        "raw_size": coerce_int(section.get("size", 0)),
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
    analyzer: SectionHost,
    section: dict[str, Any],
    analysis: dict[str, Any],
    *,
    logger: logging.Logger,
) -> dict[str, Any]:
    try:
        name = str(section.get("name", ""))
        if not isinstance(analysis, dict):
            return build_section_characteristics(name, analysis, None)
        code_analysis = (
            analyzer._analyze_code_section(section) if analysis.get("is_executable") else None
        )
        return build_section_characteristics(name, analysis, code_analysis)
    except Exception as exc:
        logger.error("Error getting section characteristics: %s", exc)
        return {}


def _function_size_stats(functions: list[Any]) -> dict[str, Any]:
    sizes = [
        size
        for f in functions
        if isinstance(f, dict) and (size := coerce_int(f.get("size", 0))) and size > 0
    ]
    if not sizes:
        return {}
    return {
        "avg_function_size": sum(sizes) / len(sizes),
        "min_function_size": min(sizes),
        "max_function_size": max(sizes),
    }


def _nop_stats(analyzer: SectionHost, vaddr: int, size: int) -> dict[str, Any]:
    nop_count, sample_size = analyzer._count_nops_in_section(vaddr, size)
    if sample_size <= 0:
        return {}
    stats: dict[str, Any] = {
        "nop_sample_size": sample_size,
        "nop_count": nop_count,
        "nop_ratio": nop_count / sample_size,
    }
    if nop_count > sample_size / 100:
        stats["excessive_nops"] = True
    return stats


def analyze_code_section(
    analyzer: SectionHost, section: dict[str, Any], *, logger: logging.Logger
) -> dict[str, Any]:
    code_info: dict[str, Any] = {}
    try:
        vaddr = coerce_int(section.get("vaddr", 0))
        size = coerce_int(section.get("size", 0))
        if size == 0:
            return code_info
        # Functions carry virtual addresses and the section spans vsize bytes in
        # memory, so the address window must use the virtual size, not the raw
        # file size — a section whose vsize exceeds its on-disk size (alignment
        # padding) otherwise drops every function past the raw-size boundary.
        vsize = coerce_int(section.get("vsize", 0))
        functions = analyzer._get_functions_in_section(vaddr, vsize or size)
        code_info["function_count"] = len(functions)
        if functions:
            code_info.update(_function_size_stats(functions))
        code_info.update(_nop_stats(analyzer, vaddr, size))
    except Exception as exc:
        logger.error("Error analyzing code section: %s", exc)
    return code_info
