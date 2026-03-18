"""Collection helpers for compiler detection."""

from __future__ import annotations

from typing import Any, cast

from ..infrastructure.command_helpers import cmd as cmd_helper
from .compiler_domain import (
    extract_import_names,
    extract_section_names,
    extract_symbol_names,
    parse_strings_output,
)


def get_file_format(detector: Any, detect_file_format_fn: Any, logger: Any) -> str:
    try:
        return str(detect_file_format_fn(detector._get_file_info(), logger=logger))
    except Exception as exc:
        logger.debug("Error detecting file format: %s", exc)
        return "Unknown"


def get_strings(detector: Any, logger: Any) -> list[str]:
    try:
        if detector.adapter is not None and hasattr(detector.adapter, "get_strings"):
            entries = detector.adapter.get_strings()
            return [entry.get("string", "") for entry in entries if entry.get("string")]
        strings_output = get_strings_raw(detector)
        return parse_strings_output(strings_output)
    except Exception as exc:
        logger.error("Error extracting strings: %s", exc)
        return []


def get_imports(detector: Any, logger: Any) -> list[str]:
    try:
        return extract_import_names(detector._get_imports_raw())
    except Exception as exc:
        logger.error("Error getting imports: %s", exc)
        return []


def get_sections(detector: Any, logger: Any) -> list[str]:
    try:
        return extract_section_names(detector._get_sections_raw())
    except Exception as exc:
        logger.error("Error getting sections: %s", exc)
        return []


def get_symbols(detector: Any, logger: Any) -> list[str]:
    try:
        return extract_symbol_names(detector._get_symbols_raw())
    except Exception as exc:
        logger.error("Error getting symbols: %s", exc)
        return []


def get_strings_raw(detector: Any) -> str:
    result = cmd_helper(detector.adapter, detector.r2, "izz~..")
    return result if isinstance(result, str) else ""


def coerce_dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def get_file_info(detector: Any) -> dict[str, Any]:
    if detector.adapter is not None and hasattr(detector.adapter, "get_file_info"):
        return cast(dict[str, Any], detector.adapter.get_file_info())
    return {}
