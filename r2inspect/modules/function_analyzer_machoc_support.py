"""MACHOC hashing and summary helpers for function analysis."""

from __future__ import annotations

from typing import Any

from ..domain.services.function_analysis import group_functions_by_machoc_hash


def generate_machoc_hashes(
    analyzer: Any, functions: list[dict[str, Any]], logger: Any
) -> dict[str, str]:
    machoc_hashes: dict[str, str] = {}
    failed_functions = 0
    logger.debug("Starting MACHOC hash generation for %s functions", len(functions))
    for i, func in enumerate(functions):
        try:
            result = analyzer._process_single_function_hash(func, i, len(functions))
            if result:
                func_name, machoc_hash = result
                machoc_hashes[func_name] = machoc_hash
            else:
                failed_functions += 1
        except Exception as exc:
            logger.error(
                "Error generating MACHOC hash for function %s: %s",
                func.get("name", "unknown"),
                str(exc),
            )
            failed_functions += 1
    logger.debug(
        "Generated MACHOC hashes for %s/%s functions (%s failed)",
        len(machoc_hashes),
        len(functions),
        failed_functions,
    )
    return machoc_hashes


def process_single_function_hash(
    analyzer: Any,
    func: dict[str, Any],
    index: int,
    total: int,
    logger: Any,
    *,
    machoc_hash_fn: Any,
) -> tuple[str, str] | None:
    func_name = func.get("name", f"func_{func.get('addr', 'unknown')}")
    func_offset = func.get("addr")
    func_size = func.get("size", 0)
    if func_offset is None:
        logger.warning("No address found for function %s", func_name)
        return None
    logger.debug(
        "Processing function %s/%s: %s at 0x%x (size: %s)",
        index + 1,
        total,
        func_name,
        func_offset,
        func_size,
    )
    mnemonics = analyzer._extract_function_mnemonics(func_name, func_size, func_offset)
    if not mnemonics:
        logger.warning("No mnemonics found for function %s (size: %s)", func_name, func_size)
        return None
    machoc_hash = machoc_hash_fn(mnemonics)
    if not machoc_hash:
        return None
    logger.debug(
        "Generated MACHOC hash for %s: %s... (%s mnemonics)",
        func_name,
        machoc_hash[:16],
        len(mnemonics),
    )
    return func_name, machoc_hash


def get_function_similarity(machoc_hashes: dict[str, str], logger: Any) -> dict[str, list[str]]:
    try:
        similarities = group_functions_by_machoc_hash(machoc_hashes)
        if similarities:
            logger.debug(
                "Found %s MACHOC hash collisions indicating similar functions",
                len(similarities),
            )
        return similarities
    except Exception as exc:
        logger.error("Error calculating function similarity: %s", str(exc))
        return {}


def generate_machoc_summary(
    analysis_results: dict[str, Any], logger: Any, *, similarity_fn: Any
) -> dict[str, Any]:
    try:
        if not analysis_results:
            raise ValueError("No analysis results available")
        machoc_hashes = analysis_results.get("machoc_hashes", {})
        if not machoc_hashes:
            raise ValueError("No MACHOC hashes available")
        similarities = similarity_fn(machoc_hashes)
        total_duplicate_functions = sum(len(names) for names in similarities.values())
        result: dict[str, Any] = {
            "total_functions_hashed": len(machoc_hashes),
            "unique_machoc_hashes": len(set(machoc_hashes.values())),
            "duplicate_function_groups": len(similarities),
            "total_duplicate_functions": total_duplicate_functions,
        }
        if similarities:
            sorted_patterns = sorted(
                similarities.items(),
                key=lambda item: len(item[1]),
                reverse=True,
            )
            result["similarities"] = similarities
            result["most_common_patterns"] = [
                {
                    "machoc_hash": machoc_hash,
                    "function_count": len(function_names),
                    "functions": function_names,
                }
                for machoc_hash, function_names in sorted_patterns[:5]
            ]
        return result
    except Exception as exc:
        logger.error("Error generating MACHOC summary: %s", str(exc))
        return {"error": f"Summary generation failed: {str(exc)}"}
