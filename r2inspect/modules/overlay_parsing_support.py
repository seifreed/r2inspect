"""Parsing helpers for overlay analysis."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def get_file_size(cmdj: Callable[[str, Any], Any]) -> int | None:
    file_info = cmdj("ij", {})
    if not isinstance(file_info, dict):
        return None
    file_size = file_info.get("core", {}).get("size", 0)
    if not file_size:
        return None
    try:
        return int(file_size)
    except (ValueError, TypeError):
        return None


def get_valid_pe_end(calculate_pe_end: Callable[[], int], file_size: int) -> int | None:
    pe_end = calculate_pe_end()
    if not pe_end:
        return None
    try:
        pe_end_int = int(pe_end)
    except (ValueError, TypeError):
        return None
    if pe_end_int == 0 or pe_end_int >= file_size:
        return None
    return pe_end_int


def calculate_pe_end(
    cmdj: Callable[[str, Any], Any],
    *,
    logger: Any,
    get_sections_fn: Callable[[], list[dict[str, Any]]],
    get_max_section_end_fn: Callable[[list[dict[str, Any]]], int],
    extend_end_with_certificate_fn: Callable[[int], int],
) -> int:
    try:
        sections = get_sections_fn()
        if not sections:
            return 0
        max_end = get_max_section_end_fn(sections)
        return extend_end_with_certificate_fn(max_end)
    except Exception as exc:
        logger.error("Error calculating PE end: %s", exc)
        return 0


def get_sections(cmdj: Callable[[str, Any], Any]) -> list[dict[str, Any]]:
    sections = cmdj("iSj", [])
    if not isinstance(sections, list):
        return []
    return [section for section in sections if isinstance(section, dict)]


def get_max_section_end(sections: list[dict[str, Any]]) -> int:
    max_end = 0
    for section in sections:
        section_end = section.get("paddr", 0) + section.get("size", 0)
        if section_end > max_end:
            max_end = section_end
    return max_end


def extend_end_with_certificate(cmdj: Callable[[str, Any], Any], max_end: int) -> int:
    data_dirs = cmdj("iDj", [])
    if not isinstance(data_dirs, list):
        return max_end
    for dd in data_dirs:
        if not isinstance(dd, dict) or dd.get("name") != "SECURITY":
            continue
        cert_offset = dd.get("paddr", 0)
        cert_size = dd.get("size", 0)
        if cert_offset > 0 and cert_size > 0:
            max_end = max(max_end, cert_offset + cert_size)
    return max_end
