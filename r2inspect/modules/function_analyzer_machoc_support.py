"""MACHOC hashing and summary helpers for function analysis."""

from __future__ import annotations

import logging
from typing import Any, Protocol

from ..domain.services.function_analysis import group_functions_by_machoc_hash


def _coerce_function_list(functions: Any) -> list[dict[str, Any]]:
    if isinstance(functions, list):
        return [func for func in functions if isinstance(func, dict)]
    try:
        return [func for func in list(functions) if isinstance(func, dict)]
    except TypeError:
        return []


def _to_int(value: Any) -> int:
    try:
        if isinstance(value, str):
            return int(value, 0)
        return int(value)
    except (TypeError, ValueError):
        return 0


def _function_name(func: Any, func_offset: int | None = None) -> str:
    if not isinstance(func, dict):
        if func_offset is not None and func_offset > 0:
            return f"func_{func_offset}"
        return "unknown"
    name = func.get("name")
    if isinstance(name, str) and name:
        return name
    if func_offset is not None and func_offset > 0:
        return f"func_{func_offset}"
    return "unknown"


class FunctionMachocHost(Protocol):
    """Overridable collaboration contract the MACHOC helpers depend on."""

    def _process_single_function_hash(
        self, func: dict[str, Any], index: int, total: int
    ) -> tuple[str, str] | None: ...
    def _extract_function_mnemonics(
        self, func_name: str, func_size: int, func_addr: int
    ) -> list[str]: ...


def generate_machoc_hashes(
    analyzer: FunctionMachocHost, functions: list[dict[str, Any]], logger: logging.Logger
) -> dict[str, str]:
    machoc_hashes: dict[str, str] = {}
    failed_functions = 0
    normalized = _coerce_function_list(functions)
    if not normalized:
        return machoc_hashes
    logger.debug("Starting MACHOC hash generation for %s functions", len(normalized))
    for i, func in enumerate(normalized):
        try:
            result = analyzer._process_single_function_hash(func, i, len(normalized))
            if result:
                func_name, machoc_hash = result
                machoc_hashes[func_name] = machoc_hash
            else:
                failed_functions += 1
        except Exception as exc:
            logger.error(
                "Error generating MACHOC hash for function %s: %s",
                _function_name(func),
                str(exc),
            )
            failed_functions += 1
    logger.debug(
        "Generated MACHOC hashes for %s/%s functions (%s failed)",
        len(machoc_hashes),
        len(normalized),
        failed_functions,
    )
    return machoc_hashes


def process_single_function_hash(
    analyzer: FunctionMachocHost,
    func: dict[str, Any],
    index: int,
    total: int,
    logger: logging.Logger,
    *,
    machoc_hash_fn: Any,
) -> tuple[str, str] | None:
    func_offset = _to_int(func.get("addr"))
    func_size = _to_int(func.get("size", 0))
    func_name = _function_name(func, func_offset)
    if func_offset <= 0:
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


def get_function_similarity(
    machoc_hashes: dict[str, str], logger: logging.Logger
) -> dict[str, list[str]]:
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
    analysis_results: dict[str, Any], logger: logging.Logger, *, similarity_fn: Any
) -> dict[str, Any]:
    try:
        if not analysis_results:
            raise ValueError("No analysis results available")
        machoc_hashes = analysis_results.get("machoc_hashes", {})
        if not machoc_hashes:
            raise ValueError("No MACHOC hashes available")
        similarities = similarity_fn(machoc_hashes)
        if not isinstance(similarities, dict):
            similarities = {}
        valid_similarities = {
            machoc_hash: function_names
            for machoc_hash, function_names in similarities.items()
            if isinstance(function_names, list)
        }
        total_duplicate_functions = sum(len(names) for names in valid_similarities.values())
        valid_hashes = {
            value for value in machoc_hashes.values() if isinstance(value, str) and value
        }
        result: dict[str, Any] = {
            "total_functions_hashed": len(machoc_hashes),
            "unique_machoc_hashes": len(valid_hashes),
            "duplicate_function_groups": len(valid_similarities),
            "total_duplicate_functions": total_duplicate_functions,
        }
        if valid_similarities:
            sorted_patterns = sorted(
                valid_similarities.items(),
                key=lambda item: len(item[1]),
                reverse=True,
            )
            result["similarities"] = valid_similarities
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
