"""Helpers for detailed TLSH section and function analysis.

The helpers are Template-Methods over the host analyzer's overridable steps
(subclasses script ``_get_sections`` / ``_read_bytes_hex`` /
``_calculate_tlsh_from_hex`` in tests), so they depend on the explicit
:class:`TlshHost` protocol rather than an untyped host.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol, cast


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
    result["section_tlsh"] = host._calculate_section_tlsh()
    stats = cast(dict[str, int], result["stats"])
    section_hashes = cast(dict[str, str | None], result["section_tlsh"])
    stats["sections_analyzed"] = len(section_hashes)
    stats["sections_with_tlsh"] = sum(1 for value in section_hashes.values() if value)
    result["text_section_tlsh"] = section_hashes.get(".text")
    result["function_tlsh"] = host._calculate_function_tlsh()
    function_hashes = cast(dict[str, str | None], result["function_tlsh"])
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
            section_name = section.get("name", "unknown")
            vaddr = section.get("vaddr", 0)
            size = section.get("size", 0)
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


def calculate_function_tlsh(host: TlshHost, logger: logging.Logger) -> dict[str, str | None]:
    function_hashes: dict[str, str | None] = {}
    try:
        functions = host._get_functions()
        if not functions:
            return function_hashes
        for func in functions[:50]:
            if not isinstance(func, dict):
                logger.debug("Skipping malformed function data: %s - %s", type(func), func)
                continue
            func_name = func.get("name", f"func_{func.get('addr', 'unknown')}")
            func_addr = func.get("addr")
            func_size = func.get("size", 0)
            if not func_addr or func_size == 0 or func_size > 100000:
                function_hashes[func_name] = None
                continue
            try:
                hex_data = host._read_bytes_hex(func_addr, func_size)
                function_hashes[func_name] = host._calculate_tlsh_from_hex(hex_data)
            except Exception as exc:
                logger.debug("Error calculating TLSH for function %s: %s", func_name, exc)
                function_hashes[func_name] = None
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
        similar_pairs: list[dict[str, Any]] = []
        section_names = list(section_hashes.keys())
        for index, name1 in enumerate(section_names):
            hash1 = section_hashes[name1]
            if not hash1:
                continue
            for name2 in section_names[index + 1 :]:
                hash2 = section_hashes[name2]
                if not hash2:
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
