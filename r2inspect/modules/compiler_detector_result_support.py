"""Result shaping helpers for compiler detection."""

from __future__ import annotations

from typing import Any


def init_compiler_result() -> dict[str, Any]:
    return {
        "detected": False,
        "compiler": "Unknown",
        "version": "Unknown",
        "confidence": 0.0,
        "details": {},
        "signatures_found": [],
        "rich_header_info": {},
    }


def gather_detection_inputs(
    detector: Any,
) -> tuple[str, list[str], list[str], list[str], list[str]]:
    file_format = detector._get_file_format()
    strings_data = detector._get_strings()
    imports_data = detector._get_imports()
    sections_data = detector._get_sections()
    symbols_data = detector._get_symbols()
    return file_format, strings_data, imports_data, sections_data, symbols_data
