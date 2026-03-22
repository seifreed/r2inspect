#!/usr/bin/env python3
"""Compiler detection module."""

from typing import Any

from ..infrastructure.command_helpers import cmd as cmd_helper
from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..infrastructure.logging import get_logger
from .compiler_detector_collection_support import (
    get_file_format as _get_file_format_impl2,
    get_file_info as _get_file_info_impl2,
    get_imports as _get_imports_impl2,
    get_sections as _get_sections_impl2,
    get_strings as _get_strings_impl2,
    get_strings_raw as _get_strings_raw_impl2,
    get_symbols as _get_symbols_impl2,
)
from .compiler_detector_result_support import (
    gather_detection_inputs as _gather_detection_inputs_impl,
    init_compiler_result as _init_compiler_result_impl,
)
from .compiler_detector_support import (
    analyze_rich_header as _analyze_rich_header_logic,
    apply_best_compiler as _apply_best_compiler_logic,
    apply_rich_header_detection as _apply_rich_header_detection_logic,
    detect_compiler_version as _detect_compiler_version_logic,
    detect_file_format as _detect_file_format_logic,
    score_compilers as _score_compilers_logic,
)
from ..domain.formats.compiler import (
    calculate_compiler_score,
    detect_clang_version,
    detect_gcc_version,
    detect_go_version,
    detect_msvc_version,
    detect_rust_version,
    detection_method,
    extract_import_names,
    extract_section_names,
    extract_symbol_names,
    map_msvc_version_from_rich,
    parse_strings_output,
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

# Constants


class CompilerDetector(CommandHelperMixin):
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
        """Main function to detect compiler information"""

        logger.debug("Starting compiler detection...")

        results = _init_compiler_result_impl()

        try:
            file_format, strings_data, imports_data, sections_data, symbols_data = (
                _gather_detection_inputs_impl(self)
            )

            # PE-specific analysis
            if file_format == "PE":
                if self._apply_rich_header_detection(results):
                    return results

            # Score each compiler
            compiler_scores = self._score_compilers(
                strings_data, imports_data, sections_data, symbols_data
            )
            self._apply_best_compiler(
                results, compiler_scores, strings_data, imports_data, file_format
            )

            logger.debug(
                f"Compiler detection completed: {results['compiler']} (confidence: {results['confidence']:.2f})"
            )

        except Exception as e:
            logger.error("Error during compiler detection: %s", e)
            results["error"] = str(e)

        return results

    def _apply_rich_header_detection(self, results: dict[str, Any]) -> bool:
        return _apply_rich_header_detection_logic(
            self, results, map_msvc_version=map_msvc_version_from_rich, logger=logger
        )

    def _score_compilers(
        self,
        strings_data: list[str],
        imports_data: list[str],
        sections_data: list[str],
        symbols_data: list[str],
    ) -> dict[str, float]:
        return _score_compilers_logic(
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
        _apply_best_compiler_logic(
            results,
            compiler_scores,
            strings_data,
            imports_data,
            file_format,
            detect_version=self._detect_compiler_version,
            detection_method_fn=detection_method,
        )

    def _get_file_format(self) -> str:
        """Detect file format (PE, ELF, Mach-O)"""
        return _get_file_format_impl2(self, _detect_file_format_logic, logger)

    def _get_strings(self) -> list[str]:
        """Extract strings from binary."""
        return self._safe_call(
            lambda: (
                [e.get("string", "") for e in self.adapter.get_strings() if e.get("string")]
                if self.adapter is not None and hasattr(self.adapter, "get_strings")
                else parse_strings_output(self._get_strings_raw())
            ),
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
        return _analyze_rich_header_logic(self, logger=logger)

    def _detect_compiler_version(
        self, compiler: str, strings_data: list[str], imports_data: list[str]
    ) -> str:
        """Detect specific compiler version"""
        return _detect_compiler_version_logic(
            compiler,
            strings_data,
            imports_data,
            detectors={
                "MSVC": self._detect_msvc_version,
                "GCC": self._detect_gcc_version,
                "Clang": self._detect_clang_version,
                "Intel": self._detect_intel_version,
                "Borland": self._detect_borland_version,
                "MinGW": self._detect_mingw_version,
                "Go": self._detect_go_version,
                "Rust": self._detect_rust_version,
                "Delphi": self._detect_delphi_version,
            },
        )

    def _detect_msvc_version(self, strings_data: list[str], imports_data: list[str]) -> str:
        """Detect MSVC version"""
        return detect_msvc_version(strings_data, imports_data, self.msvc_versions)

    def _detect_gcc_version(self, strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect GCC version"""
        return detect_gcc_version(strings_data)

    def _detect_clang_version(self, strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect Clang version"""
        return detect_clang_version(strings_data)

    def _detect_intel_version(self, _strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect Intel version"""
        return "Unknown"

    def _detect_borland_version(self, _strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect Borland version"""
        return "Unknown"

    def _detect_mingw_version(self, _strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect MinGW version"""
        return "Unknown"

    def _detect_go_version(self, strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect Go version"""
        return detect_go_version(strings_data)

    def _detect_rust_version(self, strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect Rust version"""
        return detect_rust_version(strings_data)

    def _detect_delphi_version(self, _strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect Delphi version"""
        return "Unknown"

    def _get_file_info(self) -> dict[str, Any]:
        return _get_file_info_impl2(self)

    def _get_imports_raw(self) -> list[dict[str, Any]]:
        return self._coerce_dict_list(self._get_via_adapter("get_imports"))

    def _get_sections_raw(self) -> list[dict[str, Any]]:
        return self._coerce_dict_list(self._get_via_adapter("get_sections"))

    def _get_symbols_raw(self) -> list[dict[str, Any]]:
        return self._coerce_dict_list(self._get_via_adapter("get_symbols"))

    def _get_strings_raw(self) -> str:
        result = cmd_helper(self.adapter, self.adapter, "izz~..")
        return result if isinstance(result, str) else ""
