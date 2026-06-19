#!/usr/bin/env python3
"""Section analysis module."""

from typing import Any

from ..abstractions.coercion_support import coerce_int
from ..abstractions import BaseAnalyzer
from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..domain.services.section_analysis import (
    build_entropy_indicators,
    build_permission_indicators,
    build_section_characteristics,
    build_section_name_indicators,
    build_size_indicators,
    decode_pe_characteristics,
    update_section_summary,
)
from ..infrastructure.logging import get_logger
from .section_analyzer_runtime_support import (
    analyze_sections as _analyze_sections_impl,
    calculate_entropy as _calculate_entropy_impl,
    count_nops_in_section as _count_nops_in_section_impl,
    get_arch as _get_arch_impl,
    get_section_summary as _get_section_summary_impl,
)
from .section_analyzer_support import (
    analyze_code_section as _analyze_code_section_impl,
    analyze_single_section as _analyze_single_section_impl,
    get_section_characteristics as _get_section_characteristics_impl,
)
from ..domain.services.binary_helpers import (
    STANDARD_PE_SECTIONS,
    shannon_entropy,
    suspicious_section_name_indicator,
)

logger = get_logger(__name__)


def _coerce_function_list(functions: Any) -> list[Any]:
    if isinstance(functions, list):
        return functions
    try:
        return list(functions)
    except TypeError:
        return []


def _to_int(value: Any) -> int:
    return coerce_int(value)


class SectionAnalyzer(CommandHelperMixin, BaseAnalyzer):
    """Section analysis using backend data."""

    def __init__(self, adapter: Any, config: Any | None = None) -> None:
        super().__init__(adapter=adapter, config=config)

        # Standard PE section names
        self.standard_sections = STANDARD_PE_SECTIONS
        self._arch: str | None = None
        self._functions_cache: list[Any] | None = None

    def get_category(self) -> str:
        return "metadata"

    def get_description(self) -> str:
        return "Analyzes binary sections including entropy, permissions, and suspicious characteristics"

    def supports_format(self, file_format: str) -> bool:
        return file_format.upper() in {"PE", "PE32", "PE32+", "ELF", "MACH0", "MACHO"}

    def analyze(self) -> dict[str, Any]:
        """Perform section analysis"""
        result = self._init_result_structure({"total_sections": 0, "sections": [], "summary": {}})

        with self._analysis_context(result, error_message="Section analysis failed"):
            self._log_info("Starting section analysis")
            sections = self.analyze_sections()
            summary = self.get_section_summary()

            result["sections"] = sections
            result["summary"] = summary
            result["total_sections"] = len(sections)
            self._log_info(f"Analyzed {len(sections)} sections")

        return result

    def analyze_sections(self) -> list[dict[str, Any]]:
        """Analyze all sections in the PE file"""
        return _analyze_sections_impl(self, logger)

    def _analyze_single_section(self, section: dict[str, Any]) -> dict[str, Any]:
        """Analyze a single section"""
        return _analyze_single_section_impl(self, section, logger=logger)

    def _apply_permissions(self, section: dict[str, Any], analysis: dict[str, Any]) -> None:
        flags_value = section.get("flags", "")
        flags = "" if flags_value is None else str(flags_value)
        analysis["is_executable"] = "x" in flags
        analysis["is_writable"] = "w" in flags
        analysis["is_readable"] = "r" in flags

        pe_flags = section.get("perm", "")
        if pe_flags:
            analysis["is_executable"] = analysis["is_executable"] or "x" in pe_flags
            analysis["is_writable"] = analysis["is_writable"] or "w" in pe_flags
            analysis["is_readable"] = analysis["is_readable"] or "r" in pe_flags

    def _apply_pe_characteristics(self, section: dict[str, Any], analysis: dict[str, Any]) -> None:
        characteristics_value = _to_int(section.get("characteristics", 0))
        if characteristics_value <= 0:
            return
        analysis["pe_characteristics"] = self._decode_pe_characteristics(characteristics_value)
        if "IMAGE_SCN_MEM_EXECUTE" in analysis["pe_characteristics"]:
            analysis["is_executable"] = True
        if "IMAGE_SCN_MEM_WRITE" in analysis["pe_characteristics"]:
            analysis["is_writable"] = True
        if "IMAGE_SCN_MEM_READ" in analysis["pe_characteristics"]:
            analysis["is_readable"] = True

    def _calculate_size_ratio(self, analysis: dict[str, Any]) -> float:
        vsize = analysis.get("virtual_size", 0)
        raw_size = analysis.get("raw_size", 0)
        if raw_size <= 0:
            return 0.0
        return vsize / raw_size if vsize > 0 else 0.0

    def _calculate_entropy(self, section: dict[str, Any]) -> float:
        return _calculate_entropy_impl(self, section, logger)

    def _check_suspicious_characteristics(
        self, section: dict[str, Any], analysis: dict[str, Any]
    ) -> list[str]:
        """Check for suspicious section characteristics"""
        indicators = []

        try:
            name = str(section.get("name", ""))
            vsize = _to_int(section.get("vsize", 0))
            raw_size = _to_int(section.get("size", 0))
            entropy = analysis.get("entropy", 0)

            indicators.extend(self._check_section_name_indicators(name))
            indicators.extend(self._check_permission_indicators(analysis))
            indicators.extend(self._check_entropy_indicators(entropy))
            indicators.extend(self._check_size_indicators(vsize, raw_size))

        except (RuntimeError, TypeError, ValueError, AttributeError) as exc:
            section_name = section.get("name", "?") if isinstance(section, dict) else "?"
            logger.error(
                "Error checking suspicious characteristics for section %s: %s",
                section_name,
                exc,
            )

        return indicators

    def _check_section_name_indicators(self, name: str) -> list[str]:
        """Check for suspicious section name indicators"""
        return build_section_name_indicators(
            name,
            set(self.standard_sections),
            suspicious_section_name_indicator,
        )

    def _check_permission_indicators(self, analysis: dict[str, Any]) -> list[str]:
        """Check for suspicious permission indicators"""
        return build_permission_indicators(analysis)

    def _check_entropy_indicators(self, entropy: float) -> list[str]:
        """Check for entropy-based indicators"""
        return build_entropy_indicators(entropy)

    def _check_size_indicators(self, vsize: int, raw_size: int) -> list[str]:
        """Check for size-based indicators"""
        return build_size_indicators(vsize, raw_size)

    def _decode_pe_characteristics(self, characteristics: int) -> list[str]:
        """Decode PE section characteristics flags"""
        return decode_pe_characteristics(characteristics)

    def _get_section_characteristics(
        self, section: dict[str, Any], analysis: dict[str, Any]
    ) -> dict[str, Any]:
        """Get detailed section characteristics"""
        return _get_section_characteristics_impl(self, section, analysis, logger=logger)

    def _analyze_code_section(self, section: dict[str, Any]) -> dict[str, Any]:
        """Analyze executable code sections"""
        return _analyze_code_section_impl(self, section, logger=logger)

    def _get_functions_in_section(self, vaddr: int, size: int) -> list[dict[str, Any]]:
        if size <= 0:
            return []
        if self._functions_cache is None:
            self._functions_cache = _coerce_function_list(self._cmd_list("aflj"))
        functions = self._functions_cache or []
        end = vaddr + size
        filtered: list[dict[str, Any]] = []
        for func in functions:
            if not isinstance(func, dict):
                continue
            addr = func.get("offset", func.get("addr"))
            try:
                addr_int = int(addr, 0) if isinstance(addr, str) else int(addr)
            except (TypeError, ValueError):
                continue
            if vaddr <= addr_int < end:
                filtered.append(func)
        return filtered

    def _count_nops_in_section(self, vaddr: int, size: int) -> tuple[int, int]:
        return _count_nops_in_section_impl(self, vaddr, size)

    def _get_arch(self) -> str | None:
        return _get_arch_impl(self, logger)

    def get_section_summary(self) -> dict[str, Any]:
        """Get summary of all sections"""
        return _get_section_summary_impl(self, logger, update_section_summary)


__all__ = [
    "build_section_characteristics",
    "shannon_entropy",
]
