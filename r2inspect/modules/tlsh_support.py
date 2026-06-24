"""Helpers for detailed TLSH section and function analysis.

The helpers are Template-Methods over the host analyzer's overridable steps
(subclasses script ``_get_sections`` / ``_read_bytes_hex`` /
``_calculate_tlsh_from_hex`` in tests), so they depend on the explicit
:class:`TlshHost` protocol rather than an untyped host.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any, Protocol

from ..abstractions.coercion_support import coerce_dict, coerce_int


class TlshHost(Protocol):
    """Overridable collaboration contract the TLSH helpers depend on."""

    def _calculate_binary_tlsh(self) -> str | None: ...
    def _calculate_section_tlsh(self) -> dict[str, str | None]: ...
    def _calculate_function_tlsh(self) -> dict[str, str | None]: ...
    def _get_sections(self) -> list[Any]: ...
    def _get_functions(self) -> list[Any]: ...
    def _read_bytes_hex(self, vaddr: int, size: int) -> str | None: ...
    def _calculate_tlsh_from_hex(self, hex_data: str | None) -> str | None: ...
    def analyze_sections(self) -> dict[str, Any]: ...
    def compare_tlsh(self, hash1: str, hash2: str) -> int | None: ...


def build_detailed_analysis(host: TlshHost, available: bool) -> dict[str, Any]:
    if not available:
        return {"available": False, "error": "TLSH library not installed"}

    result: dict[str, Any] = {
        "available": True,
        "binary_tlsh": None,
        "text_section_tlsh": None,
        "section_tlsh": {},
        "function_tlsh": {},
        "stats": {
            "sections_analyzed": 0,
            "sections_with_tlsh": 0,
            "functions_analyzed": 0,
            "functions_with_tlsh": 0,
        },
    }
    result["binary_tlsh"] = host._calculate_binary_tlsh()
    section_hashes_raw = host._calculate_section_tlsh()
    section_hashes = coerce_dict(section_hashes_raw)
    result["section_tlsh"] = section_hashes
    stats_raw = result.get("stats", {})
    stats = coerce_dict(stats_raw)
    result["stats"] = stats
    stats["sections_analyzed"] = len(section_hashes)
    stats["sections_with_tlsh"] = sum(1 for value in section_hashes.values() if value)
    result["text_section_tlsh"] = section_hashes.get(".text")
    function_hashes_raw = host._calculate_function_tlsh()
    function_hashes = coerce_dict(function_hashes_raw)
    result["function_tlsh"] = function_hashes
    stats["functions_analyzed"] = len(function_hashes)
    stats["functions_with_tlsh"] = sum(1 for value in function_hashes.values() if value)
    return result


def calculate_section_tlsh(host: TlshHost, logger: logging.Logger) -> dict[str, str | None]:
    section_hashes: dict[str, str | None] = {}
    try:
        sections = host._get_sections()
        if not sections:
            return section_hashes
        for section in sections:
            if not isinstance(section, dict):
                logger.debug("Skipping malformed section data: %s - %s", type(section), section)
                continue
            section_name = section.get("name", "unknown")
            section_name = (
                section_name if isinstance(section_name, str) and section_name else "unknown"
            )
            vaddr = coerce_int(section.get("vaddr", 0))
            size = coerce_int(section.get("size", 0))
            if size == 0 or size > 50 * 1024 * 1024:
                section_hashes[section_name] = None
                continue
            try:
                read_size = min(size, 1024 * 1024)
                hex_data = host._read_bytes_hex(vaddr, read_size)
                section_hashes[section_name] = host._calculate_tlsh_from_hex(hex_data)
            except Exception as exc:
                logger.debug("Error calculating TLSH for section %s: %s", section_name, exc)
                section_hashes[section_name] = None
    except Exception as exc:
        logger.error("Error in section TLSH calculation: %s", exc)
    return section_hashes


def _tlsh_for_function(
    host: TlshHost, func: dict[str, Any], logger: logging.Logger
) -> tuple[str, str | None]:
    func_addr = coerce_int(func.get("addr", func.get("offset", 0)))
    func_name_value = func.get("name")
    func_name = (
        func_name_value
        if isinstance(func_name_value, str) and func_name_value
        else f"func_{func_addr or 'unknown'}"
    )
    func_size = coerce_int(func.get("size", 0))
    if not func_addr or func_size == 0 or func_size > 100000:
        return func_name, None
    try:
        hex_data = host._read_bytes_hex(func_addr, func_size)
        return func_name, host._calculate_tlsh_from_hex(hex_data)
    except Exception as exc:
        logger.debug("Error calculating TLSH for function %s: %s", func_name, exc)
        return func_name, None


def calculate_function_tlsh(host: TlshHost, logger: logging.Logger) -> dict[str, str | None]:
    function_hashes: dict[str, str | None] = {}
    try:
        functions = host._get_functions()
        if isinstance(functions, list):
            function_source = functions
        elif isinstance(functions, (dict, str, bytes)) or not isinstance(functions, Iterable):
            return function_hashes
        else:
            function_source = list(functions)
        for func in function_source[:50]:
            if not isinstance(func, dict):
                logger.debug("Skipping malformed function data: %s - %s", type(func), func)
                continue
            func_name, func_hash = _tlsh_for_function(host, func, logger)
            function_hashes[func_name] = func_hash
    except Exception as exc:
        logger.error("Error in function TLSH calculation: %s", exc)
    return function_hashes


def find_similar_sections(
    host: TlshHost, threshold: int, logger: logging.Logger
) -> list[dict[str, Any]]:
    try:
        analysis = host.analyze_sections()
        if not analysis.get("available"):
            return []
        section_hashes = analysis.get("section_tlsh", {})
        if not isinstance(section_hashes, dict):
            return []
        similar_pairs: list[dict[str, Any]] = []
        section_names = list(section_hashes.keys())
        for index, name1 in enumerate(section_names):
            hash1 = section_hashes[name1]
            if not isinstance(hash1, str) or not hash1:
                continue
            for name2 in section_names[index + 1 :]:
                hash2 = section_hashes[name2]
                if not isinstance(hash2, str) or not hash2:
                    continue
                similarity = host.compare_tlsh(hash1, hash2)
                if similarity is not None and similarity <= threshold:
                    similar_pairs.append(
                        {
                            "section1": name1,
                            "section2": name2,
                            "similarity_score": similarity,
                            "hash1": hash1,
                            "hash2": hash2,
                        }
                    )
        return sorted(similar_pairs, key=lambda item: item["similarity_score"])
    except Exception as exc:
        logger.error("Error finding similar sections: %s", exc)
        return []


def similarity_level(score: int | None) -> str:
    if score is None:
        return "Unknown"
    if score == 0:
        return "Identical"
    if score <= 30:
        return "Very Similar"
    if score <= 50:
        return "Similar"
    if score <= 100:
        return "Somewhat Similar"
    if score <= 200:
        return "Different"
    return "Very Different"
