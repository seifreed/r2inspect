#!/usr/bin/env python3
"""Compiler detection module."""

from typing import Any

from ..infrastructure.command_helpers import cmd as cmd_helper
from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..infrastructure.logging import get_logger
from .compiler_detector_collection_support import (
    get_file_format as _collect_file_format,
    get_file_info as _collect_file_info,
    get_strings as _collect_strings,
)
from .compiler_detector_result_support import (
    gather_detection_inputs as _gather_detection_inputs,
    init_compiler_result as _init_compiler_result,
)
from .compiler_detector_support import (
    analyze_rich_header as _analyze_rich_header,
    apply_best_compiler as _apply_best_compiler,
    apply_rich_header_detection as _apply_rich_header_detection,
    detect_file_format as _detect_file_format,
    score_compilers as _score_compilers,
)
from .compiler_version_detection import CompilerVersionDetectionMixin
from ..domain.formats.compiler import (
    calculate_compiler_score,
    detection_method,
    extract_import_names,
    extract_section_names,
    extract_symbol_names,
    map_msvc_version_from_rich,
)
from .compiler_signatures import (
    COMPILER_SIGNATURES,
    DLL_ADVAPI32,
    DLL_SHELL32,
    SECTION_DATA,
    SECTION_EH_FRAME,
    SECTION_RDATA,
    SECTION_TEXT,
)

logger = get_logger(__name__)

# Maps radare2's lowercase ``bin.compiler`` values onto the canonical names this
# detector uses elsewhere; unmapped values pass through unchanged.
_R2_COMPILER_NAMES = {
    "clang": "Clang",
    "gcc": "GCC",
    "msvc": "MSVC",
    "rustc": "Rust",
    "c": "C",
    "cpp": "C++",
}

# Constants


class CompilerDetector(CommandHelperMixin, CompilerVersionDetectionMixin):
    """Detects compiler information from binaries."""

    def __init__(self, adapter: Any, config: Any | None = None) -> None:
        self.adapter = adapter
        self.config = config

        # Compiler signatures and patterns
        self.compiler_signatures: dict[str, Any] = COMPILER_SIGNATURES

        # MSVC version mapping based on runtime libraries
        self.msvc_versions = {
            "MSVCR80.dll": "Visual Studio 2005 (8.0)",
            "MSVCR90.dll": "Visual Studio 2008 (9.0)",
            "MSVCR100.dll": "Visual Studio 2010 (10.0)",
            "MSVCR110.dll": "Visual Studio 2012 (11.0)",
            "MSVCR120.dll": "Visual Studio 2013 (12.0)",
            "MSVCR140.dll": "Visual Studio 2015/2017/2019/2022 (14.x)",
            "VCRUNTIME140.dll": "Visual Studio 2015/2017/2019/2022 (14.x)",
            "VCRUNTIME140_1.dll": "Visual Studio 2019/2022 (14.2+)",
        }

    def analyze(self) -> dict[str, Any]:
        """Unified entry point for pipeline dispatch."""
        return self.detect_compiler()

    def detect_compiler(self) -> dict[str, Any]:
        """Detect compiler used to build the binary.

        Returns a dict with keys: compiler, version, confidence, method, error.
        For PE files, Rich Header analysis is attempted first.
        """

        logger.debug("Starting compiler detection...")

        results = _init_compiler_result()

        try:
            file_format, strings_data, imports_data, sections_data, symbols_data = (
                _gather_detection_inputs(self)
            )

            # PE-specific analysis
            if file_format == "PE" and self._apply_rich_header_detection(results):
                return results

            # Score each compiler
            compiler_scores = self._score_compilers(
                strings_data, imports_data, sections_data, symbols_data
            )
            self._apply_best_compiler(
                results, compiler_scores, strings_data, imports_data, file_format
            )

            if results["compiler"] == "Unknown":
                self._apply_r2_metadata_compiler(results)

            logger.debug(
                "Compiler detection completed: %s (confidence: %.2f)",
                results["compiler"],
                results["confidence"],
            )

        except Exception as e:
            logger.error("Error during compiler detection: %s", e)
            results["error"] = str(e)

        return results

    def _apply_r2_metadata_compiler(self, results: dict[str, Any]) -> None:
        """Fill in the compiler from radare2's own ``bin`` metadata when signature
        scoring found nothing. r2 derives it from load commands / build info (e.g. a
        stripped clang Mach-O carries no string signature but r2 still reports
        ``clang``; PEs usually leave ``bin.compiler`` empty but still report
        ``bin.lang`` such as ``msvc``), so this only ever upgrades an otherwise
        Unknown result."""
        raw = self._get_r2_compiler()
        if not raw:
            return
        results["detected"] = True
        results["compiler"] = _R2_COMPILER_NAMES.get(raw.lower(), raw)
        results["confidence"] = 0.6
        results["details"]["detection_method"] = "radare2 bin metadata"

    def _get_r2_compiler(self) -> str:
        empty: dict[str, Any] = {}
        file_info = self._safe_call(
            lambda: _collect_file_info(self),
            default=empty,
            error_msg="Error reading file info for compiler metadata",
        )
        bin_info = file_info.get("bin", {}) if isinstance(file_info, dict) else {}
        if not isinstance(bin_info, dict):
            return ""
        compiler = bin_info.get("compiler")
        if isinstance(compiler, str) and compiler.strip():
            return compiler.strip()
        # r2 commonly leaves bin.compiler empty for PEs but still reports bin.lang
        # (e.g. "msvc"/"c"/"cpp"); use it as the authoritative fallback.
        lang = bin_info.get("lang")
        return lang.strip() if isinstance(lang, str) else ""

    def _apply_rich_header_detection(self, results: dict[str, Any]) -> bool:
        return _apply_rich_header_detection(
            self, results, map_msvc_version=map_msvc_version_from_rich, logger=logger
        )

    def _score_compilers(
        self,
        strings_data: list[str],
        imports_data: list[str],
        sections_data: list[str],
        symbols_data: list[str],
    ) -> dict[str, float]:
        return _score_compilers(
            self.compiler_signatures,
            strings_data,
            imports_data,
            sections_data,
            symbols_data,
            calculate_score=calculate_compiler_score,
        )

    def _apply_best_compiler(
        self,
        results: dict[str, Any],
        compiler_scores: dict[str, float],
        strings_data: list[str],
        imports_data: list[str],
        file_format: str,
    ) -> None:
        _apply_best_compiler(
            results,
            compiler_scores,
            strings_data,
            imports_data,
            file_format,
            detect_version=self._detect_compiler_version,
            detection_method_fn=detection_method,
            compiler_signatures=self.compiler_signatures,
        )

    def _get_file_format(self) -> str:
        """Detect file format (PE, ELF, Mach-O)"""
        return _collect_file_format(self, _detect_file_format, logger)

    def _get_strings(self) -> list[str]:
        """Extract strings from binary."""
        return self._safe_call(
            lambda: _collect_strings(self, logger),
            default=[],
            error_msg="Error extracting strings",
        )

    def _get_imports(self) -> list[str]:
        """Get imported functions and libraries."""
        return self._safe_call(
            lambda: extract_import_names(self._get_imports_raw()),
            default=[],
            error_msg="Error getting imports",
        )

    def _get_sections(self) -> list[str]:
        """Get section names."""
        return self._safe_call(
            lambda: extract_section_names(self._get_sections_raw()),
            default=[],
            error_msg="Error getting sections",
        )

    def _get_symbols(self) -> list[str]:
        """Get symbol names."""
        return self._safe_call(
            lambda: extract_symbol_names(self._get_symbols_raw()),
            default=[],
            error_msg="Error getting symbols",
        )

    def _analyze_rich_header(self) -> dict[str, Any]:
        """Analyze Rich Header for PE files (MSVC specific)"""
        return _analyze_rich_header(self, logger=logger)

    def _get_file_info(self) -> dict[str, Any]:
        return _collect_file_info(self)

    def _get_imports_raw(self) -> list[dict[str, Any]]:
        return self._coerce_dict_list(self._get_via_adapter("get_imports"))

    def _get_sections_raw(self) -> list[dict[str, Any]]:
        return self._coerce_dict_list(self._get_via_adapter("get_sections"))

    def _get_symbols_raw(self) -> list[dict[str, Any]]:
        return self._coerce_dict_list(self._get_via_adapter("get_symbols"))

    def _get_strings_raw(self) -> str:
        result = cmd_helper(self.adapter, self.adapter, "izz~..")
        return result if isinstance(result, str) else ""


__all__ = [
    "DLL_ADVAPI32",
    "DLL_SHELL32",
    "SECTION_DATA",
    "SECTION_EH_FRAME",
    "SECTION_RDATA",
    "SECTION_TEXT",
]
