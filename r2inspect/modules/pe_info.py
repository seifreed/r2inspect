#!/usr/bin/env python3
"""PE info helpers."""

from __future__ import annotations

from typing import Any

from ..utils.r2_helpers import get_pe_headers
from .pe_info_domain import (
    PE32_PLUS,
    apply_optional_header_info,
    build_subsystem_info,
    characteristics_from_bin,
    characteristics_from_header,
    compute_entry_point,
    determine_pe_file_type,
    determine_pe_format,
    normalize_pe_format,
)


def get_pe_headers_info(adapter: Any, filepath: str | None, logger: Any) -> dict[str, Any]:
    info: dict[str, Any] = {}
    try:
        pe_info = adapter.get_file_info()
        if pe_info and "bin" in pe_info:
            bin_info = pe_info["bin"]

            info["architecture"] = bin_info.get("arch", "Unknown")
            info["machine"] = bin_info.get("machine", "Unknown")
            info["bits"] = bin_info.get("bits", 0)
            info["endian"] = bin_info.get("endian", "Unknown")

            pe_header = _fetch_pe_header(adapter, logger)
            file_desc = _get_file_description(filepath, logger)
            info["type"] = determine_pe_file_type(bin_info, filepath, file_desc)
            precise_format = determine_pe_format(bin_info, pe_header)
            info["format"] = normalize_pe_format(precise_format)
            if info["format"] != precise_format:
                info["precise_format"] = precise_format

            info["image_base"] = bin_info.get("baddr", 0)
            entry_info = _get_entry_info(adapter, logger)
            info["entry_point"] = compute_entry_point(bin_info, entry_info)
            info = apply_optional_header_info(info, pe_header)
    except Exception as exc:
        logger.error(f"Error getting PE headers: {exc}")
    return info


def _fetch_pe_header(adapter: Any, logger: Any) -> dict[str, Any] | None:
    try:
        return get_pe_headers(adapter)
    except Exception as exc:
        logger.debug(f"Could not get PE header details: {exc}")
        return None


def _get_entry_info(adapter: Any, logger: Any) -> list[dict[str, Any]] | None:
    try:
        if adapter is not None and hasattr(adapter, "get_entry_info"):
            entry_info = adapter.get_entry_info()
            if isinstance(entry_info, list):
                return entry_info
    except Exception as exc:
        logger.debug(f"Could not get entry point from iej: {exc}")
    return None


def _get_file_description(filepath: str | None, logger: Any) -> str | None:
    if not filepath:
        return None
    try:
        import magic

        file_desc = str(magic.from_file(filepath)).lower()
        logger.debug(f"Magic file description: {file_desc}")
        return file_desc
    except Exception as exc:
        logger.debug(f"Could not use magic for file type: {exc}")
        return None


def get_file_characteristics(adapter: Any, filepath: str | None, logger: Any) -> dict[str, Any]:
    characteristics: dict[str, Any] = {}
    try:
        pe_info = adapter.get_file_info()
        if pe_info and "bin" in pe_info:
            bin_info = pe_info["bin"]
            characteristics["has_debug"] = "debug" in bin_info

            try:
                pe_header = get_pe_headers(adapter)
                header_flags = characteristics_from_header(pe_header)
                if header_flags:
                    characteristics.update(header_flags)
                else:
                    characteristics.update(characteristics_from_bin(bin_info, filepath))
            except Exception as exc:
                logger.debug(f"Could not get PE characteristics: {exc}")
                characteristics.update(characteristics_from_bin(bin_info, filepath))
    except Exception as exc:
        logger.error(f"Error getting file characteristics: {exc}")

    return characteristics


def get_compilation_info(adapter: Any, logger: Any) -> dict[str, Any]:
    info: dict[str, Any] = {}
    try:
        pe_info = adapter.get_file_info()
        if pe_info and "bin" in pe_info:
            bin_info = pe_info["bin"]
            if "compiled" in bin_info:
                info["compile_time"] = bin_info["compiled"]
            compiler_info = _extract_compiler_info(adapter)
            if compiler_info:
                info["compiler_info"] = compiler_info
    except Exception as exc:
        logger.error(f"Error getting compilation info: {exc}")
    return info


def _extract_compiler_info(adapter: Any) -> str | None:
    if adapter is None:
        return None
    if hasattr(adapter, "get_strings_text"):
        strings_text = adapter.get_strings_text()
        if strings_text:
            filtered = [line for line in strings_text.splitlines() if "compiler" in line.lower()]
            if filtered:
                return "\n".join(filtered).strip()
    return None


def get_subsystem_info(adapter: Any, logger: Any) -> dict[str, Any]:
    info: dict[str, Any] = {}
    try:
        pe_info = adapter.get_file_info()
        if pe_info and "bin" in pe_info:
            bin_info = pe_info["bin"]
            subsystem = bin_info.get("subsys", "Unknown")
            info.update(build_subsystem_info(subsystem))
    except Exception as exc:
        logger.error(f"Error getting subsystem info: {exc}")
    return info
