"""Helpers for detailed TLSH section and function analysis."""

from __future__ import annotations

from typing import Any, cast


def build_detailed_analysis(analyzer: Any, available: bool) -> dict[str, Any]:
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
    result["binary_tlsh"] = analyzer._calculate_binary_tlsh()
    result["section_tlsh"] = analyzer._calculate_section_tlsh()
    stats = cast(dict[str, int], result["stats"])
    section_hashes = cast(dict[str, str | None], result["section_tlsh"])
    stats["sections_analyzed"] = len(section_hashes)
    stats["sections_with_tlsh"] = sum(1 for value in section_hashes.values() if value)
    result["text_section_tlsh"] = section_hashes.get(".text")
    result["function_tlsh"] = analyzer._calculate_function_tlsh()
    function_hashes = cast(dict[str, str | None], result["function_tlsh"])
    stats["functions_analyzed"] = len(function_hashes)
    stats["functions_with_tlsh"] = sum(1 for value in function_hashes.values() if value)
    return result


def calculate_section_tlsh(analyzer: Any, logger: Any) -> dict[str, str | None]:
    section_hashes: dict[str, str | None] = {}
    try:
        sections = analyzer._get_sections()
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
                hex_data = analyzer._read_bytes_hex(vaddr, read_size)
                section_hashes[section_name] = analyzer._calculate_tlsh_from_hex(hex_data)
            except Exception as exc:
                logger.debug("Error calculating TLSH for section %s: %s", section_name, exc)
                section_hashes[section_name] = None
    except Exception as exc:
        logger.error("Error in section TLSH calculation: %s", exc)
    return section_hashes


def calculate_function_tlsh(analyzer: Any, logger: Any) -> dict[str, str | None]:
    function_hashes: dict[str, str | None] = {}
    try:
        functions = analyzer._get_functions()
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
                hex_data = analyzer._read_bytes_hex(func_addr, func_size)
                function_hashes[func_name] = analyzer._calculate_tlsh_from_hex(hex_data)
            except Exception as exc:
                logger.debug("Error calculating TLSH for function %s: %s", func_name, exc)
                function_hashes[func_name] = None
    except Exception as exc:
        logger.error("Error in function TLSH calculation: %s", exc)
    return function_hashes


def find_similar_sections(analyzer: Any, threshold: int, logger: Any) -> list[dict[str, Any]]:
    try:
        analysis = analyzer.analyze_sections()
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
                similarity = analyzer.compare_tlsh(hash1, hash2)
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
