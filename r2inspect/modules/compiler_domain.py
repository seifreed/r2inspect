"""DEPRECATED: Import from r2inspect.domain.formats.compiler instead."""

from ..domain.formats.compiler import (
    calculate_compiler_score,
    detection_method,
    map_msvc_version_from_rich,
    detect_msvc_version,
    detect_gcc_version,
    detect_clang_version,
    detect_go_version,
    detect_rust_version,
    parse_strings_output,
    extract_import_names,
    extract_section_names,
    extract_symbol_names,
)

__all__ = [
    "calculate_compiler_score",
    "detection_method",
    "map_msvc_version_from_rich",
    "detect_msvc_version",
    "detect_gcc_version",
    "detect_clang_version",
    "detect_go_version",
    "detect_rust_version",
    "parse_strings_output",
    "extract_import_names",
    "extract_section_names",
    "extract_symbol_names",
]
