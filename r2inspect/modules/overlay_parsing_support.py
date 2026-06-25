"""Parsing helpers for overlay analysis."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..abstractions.coercion_support import coerce_int_or_none, coerce_list


def get_file_size(cmdj: Callable[[str, Any], Any]) -> int | None:
    file_info = cmdj("ij", {})
    if not isinstance(file_info, dict):
        return None
    core = file_info.get("core", {})
    if not isinstance(core, dict):
        return None
    file_size = coerce_int_or_none(core.get("size", 0))
    if not file_size:
        return None
    return file_size


def get_valid_pe_end(calculate_pe_end: Callable[[], int], file_size: int) -> int | None:
    pe_end = calculate_pe_end()
    if not pe_end or pe_end >= file_size:
        return None
    return pe_end


def calculate_pe_end(
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
    sections = coerce_list(cmdj("iSj", []))
    return [section for section in sections if isinstance(section, dict)]


def get_max_section_end(sections: list[dict[str, Any]]) -> int:
    max_end = 0
    for section in sections:
        paddr = coerce_int_or_none(section.get("paddr", 0))
        size = coerce_int_or_none(section.get("size", 0))
        if paddr is None or size is None:
            continue
        section_end = paddr + size
        if section_end > max_end:
            max_end = section_end
    return max_end


def extend_end_with_certificate(cmdj: Callable[[str, Any], Any], max_end: int) -> int:
    for dd in coerce_list(cmdj("iDj", [])):
        if not isinstance(dd, dict) or dd.get("name") != "SECURITY":
            continue
        cert_offset = coerce_int_or_none(dd.get("paddr", 0))
        cert_size = coerce_int_or_none(dd.get("size", 0))
        if cert_offset is None or cert_size is None:
            continue
        if cert_offset > 0 and cert_size > 0:
            max_end = max(max_end, cert_offset + cert_size)
    return max_end
