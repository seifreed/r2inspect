#!/usr/bin/env python3
"""Compiler detection module."""

from typing import Any, cast

from ..utils.command_helpers import cmd as cmd_helper
from ..utils.logger import get_logger
from .compiler_domain import (
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


class CompilerDetector:
    """Detects compiler information from binaries."""

    def __init__(self, adapter: Any, config: Any | None = None) -> None:
        self.adapter = adapter
        self.r2 = adapter
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

    def detect_compiler(self) -> dict[str, Any]:
        """Main function to detect compiler information"""

        logger.debug("Starting compiler detection...")

        results: dict[str, Any] = {
            "detected": False,
            "compiler": "Unknown",
            "version": "Unknown",
            "confidence": 0.0,
            "details": {},
            "signatures_found": [],
            "rich_header_info": {},
        }

        try:
            # Get file format first
            file_format = self._get_file_format()

            # Gather information from binary
            strings_data = self._get_strings()
            imports_data = self._get_imports()
            sections_data = self._get_sections()
            symbols_data = self._get_symbols()

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
            logger.error(f"Error during compiler detection: {e}")
            results["error"] = str(e)

        return results

    def _apply_rich_header_detection(self, results: dict[str, Any]) -> bool:
        rich_header = self._analyze_rich_header()
        results["rich_header_info"] = rich_header
        if not (rich_header.get("available") and rich_header.get("compilers")):
            return False

        for compiler_entry in rich_header["compilers"]:
            compiler_name = compiler_entry.get("compiler_name", "")
            if "MSVC" in compiler_name or "Utc" in compiler_name:
                results["detected"] = True
                results["compiler"] = "MSVC"
                results["confidence"] = 0.95
                results["version"] = map_msvc_version_from_rich(compiler_name)
                results["details"] = {"detection_method": "Rich Header Analysis"}
                logger.debug(
                    f"Detected {results['compiler']} {results['version']} from Rich Header"
                )
                return True
        return False

    def _score_compilers(
        self,
        strings_data: list[str],
        imports_data: list[str],
        sections_data: list[str],
        symbols_data: list[str],
    ) -> dict[str, float]:
        compiler_scores: dict[str, float] = {}
        for compiler_name, signatures in self.compiler_signatures.items():
            score = calculate_compiler_score(
                cast(dict[str, list[str]], signatures),
                strings_data,
                imports_data,
                sections_data,
                symbols_data,
            )
            compiler_scores[compiler_name] = score
        return compiler_scores

    def _apply_best_compiler(
        self,
        results: dict[str, Any],
        compiler_scores: dict[str, float],
        strings_data: list[str],
        imports_data: list[str],
        file_format: str,
    ) -> None:
        if not compiler_scores:
            return
        best_compiler = max(compiler_scores, key=lambda key: compiler_scores[key])
        best_score = compiler_scores[best_compiler]

        if best_score <= 0.3:
            return
        results["detected"] = True
        results["compiler"] = best_compiler
        results["confidence"] = best_score
        results["version"] = self._detect_compiler_version(
            best_compiler, strings_data, imports_data
        )
        results["details"] = {
            "all_scores": compiler_scores,
            "file_format": file_format,
            "detection_method": detection_method(best_compiler, best_score),
        }

    def _get_file_format(self) -> str:
        """Detect file format (PE, ELF, Mach-O)"""
        try:
            file_info = self._get_file_info()  # Get file info in JSON
            if file_info and "bin" in file_info:
                format_info = file_info["bin"].get("class", "").upper()
                if "PE" in format_info:
                    return "PE"
                elif "ELF" in format_info:
                    return "ELF"
                elif "MACH" in format_info:
                    return "Mach-O"
            return "Unknown"
        except Exception as e:
            logger.debug(f"Error detecting file format: {e}")
            return "Unknown"

    def _get_strings(self) -> list[str]:
        """Extract strings from binary"""
        try:
            if self.adapter is not None and hasattr(self.adapter, "get_strings"):
                entries = self.adapter.get_strings()
                return [entry.get("string", "") for entry in entries if entry.get("string")]
            strings_output = self._get_strings_raw()
            return parse_strings_output(strings_output)
        except Exception as e:
            logger.error(f"Error extracting strings: {e}")
            return []

    def _get_imports(self) -> list[str]:
        """Get imported functions and libraries"""
        try:
            imports_data = self._get_imports_raw()
            return extract_import_names(imports_data)
        except Exception as e:
            logger.error(f"Error getting imports: {e}")
            return []

    def _get_sections(self) -> list[str]:
        """Get section names"""
        try:
            sections_data = self._get_sections_raw()
            return extract_section_names(sections_data)
        except Exception as e:
            logger.error(f"Error getting sections: {e}")
            return []

    def _get_symbols(self) -> list[str]:
        """Get symbol names"""
        try:
            symbols_data = self._get_symbols_raw()
            return extract_symbol_names(symbols_data)
        except Exception as e:
            logger.error(f"Error getting symbols: {e}")
            return []

    def _analyze_rich_header(self) -> dict[str, Any]:
        """Analyze Rich Header for PE files (MSVC specific)"""
        try:
            # Use the RichHeaderAnalyzer module for proper analysis
            from .rich_header_analyzer import RichHeaderAnalyzer

            # Get the file path from r2
            file_info = self._get_file_info()
            if not file_info or "core" not in file_info:
                return {}

            filepath = file_info["core"].get("file", "")
            if not filepath:
                return {}

            # Analyze Rich Header
            rich_analyzer = RichHeaderAnalyzer(self.adapter, filepath)
            rich_info = rich_analyzer.analyze()

            return rich_info
        except Exception as e:
            logger.error(f"Error analyzing Rich header: {e}")
            return {}

    def _detect_compiler_version(
        self, compiler: str, strings_data: list[str], imports_data: list[str]
    ) -> str:
        """Detect specific compiler version"""

        version_detectors = {
            "MSVC": self._detect_msvc_version,
            "GCC": self._detect_gcc_version,
            "Clang": self._detect_clang_version,
            "Intel": self._detect_intel_version,
            "Borland": self._detect_borland_version,
            "MinGW": self._detect_mingw_version,
            "Go": self._detect_go_version,
            "Rust": self._detect_rust_version,
            "Delphi": self._detect_delphi_version,
        }

        detector = version_detectors.get(compiler)
        if detector:
            return detector(strings_data, imports_data)

        return "Unknown"

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
        if self.adapter is not None and hasattr(self.adapter, "get_file_info"):
            return cast(dict[str, Any], self.adapter.get_file_info())
        return {}

    @staticmethod
    def _coerce_dict_list(value: Any) -> list[dict[str, Any]]:
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            return [value]
        return []

    def _get_imports_raw(self) -> list[dict[str, Any]]:
        if self.adapter is not None and hasattr(self.adapter, "get_imports"):
            return self._coerce_dict_list(self.adapter.get_imports())
        return []

    def _get_sections_raw(self) -> list[dict[str, Any]]:
        if self.adapter is not None and hasattr(self.adapter, "get_sections"):
            return self._coerce_dict_list(self.adapter.get_sections())
        return []

    def _get_symbols_raw(self) -> list[dict[str, Any]]:
        if self.adapter is not None and hasattr(self.adapter, "get_symbols"):
            return self._coerce_dict_list(self.adapter.get_symbols())
        return []

    def _get_strings_raw(self) -> str:
        result = cmd_helper(self.adapter, self.r2, "izz~..")
        return result if isinstance(result, str) else ""
