"""Helpers for CCBHash function and binary analysis."""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Protocol, cast

from ..domain.services.binary_helpers import clean_function_name
from ..interfaces.binary_analyzer import BinaryAnalyzerInterface
from .function_extraction import collect_valid_functions


class CcbHashHost(Protocol):
    """Overridable collaboration contract the CCBHash helpers depend on."""

    adapter: BinaryAnalyzerInterface | None

    def _cmd_list(self, command: str) -> list[Any]: ...
    def _extract_functions(self) -> list[dict[str, Any]]: ...
    def _calculate_function_ccbhash(self, func_offset: int, func_name: str) -> str | None: ...
    def _build_canonical_representation(
        self, cfg: dict[str, Any], func_offset: int
    ) -> str | None: ...
    def _find_similar_functions(
        self, function_hashes: dict[str, dict[str, Any]]
    ) -> list[dict[str, Any]]: ...
    def _calculate_binary_ccbhash(
        self, function_hashes: dict[str, dict[str, Any]]
    ) -> str | None: ...


def build_function_ccbhashes(
    analyzer: CcbHashHost, functions: list[dict[str, Any]]
) -> tuple[dict[str, dict[str, Any]], int]:
    """Hash each function's CFG, returning the hash map and the count hashed."""
    function_hashes: dict[str, dict[str, Any]] = {}
    analyzed_count = 0
    for func in functions:
        func_name = func.get("name", f"func_{func.get('addr', 'unknown')}")
        func_offset = func.get("addr")
        if func_offset is None:
            continue
        ccbhash = analyzer._calculate_function_ccbhash(func_offset, func_name)
        if ccbhash:
            function_hashes[func_name] = {
                "ccbhash": ccbhash,
                "addr": func_offset,
                "size": func.get("size", 0),
            }
            analyzed_count += 1
    return function_hashes, analyzed_count


def analyze_functions(
    analyzer: CcbHashHost,
    logger: logging.Logger,
    no_functions_found: str,
    no_functions_analyzed: str,
) -> dict[str, Any]:
    results = {
        "available": False,
        "function_hashes": {},
        "total_functions": 0,
        "analyzed_functions": 0,
        "unique_hashes": 0,
        "similar_functions": [],
        "binary_ccbhash": None,
        "error": None,
    }
    try:
        functions = analyzer._extract_functions()
        if not functions:
            results["error"] = no_functions_found
            logger.debug(no_functions_found)
            return results
        results["total_functions"] = len(functions)
        function_hashes, analyzed_count = build_function_ccbhashes(analyzer, functions)
        if not function_hashes:
            results["error"] = no_functions_analyzed
            logger.debug(no_functions_analyzed)
            return results
        unique_hashes = {item["ccbhash"] for item in function_hashes.values()}
        results["available"] = True
        results["function_hashes"] = function_hashes
        results["analyzed_functions"] = analyzed_count
        results["unique_hashes"] = len(unique_hashes)
        results["similar_functions"] = analyzer._find_similar_functions(function_hashes)
        results["binary_ccbhash"] = analyzer._calculate_binary_ccbhash(function_hashes)
    except Exception as exc:
        logger.error("CCBHash analysis failed: %s", exc)
        results["error"] = str(exc)
    return results


def extract_functions(analyzer: CcbHashHost, logger: logging.Logger) -> list[dict[str, Any]]:
    try:
        return collect_valid_functions(analyzer, logger, clean_names=True)
    except Exception as exc:
        logger.error("Error extracting functions: %s", exc)
        return []


def build_canonical_representation(cfg: dict[str, Any], func_offset: int) -> str | None:
    edges = cfg.get("edges", [])
    if edges:
        edge_strs = []
        for edge in edges:
            src = edge.get("src")
            dst = edge.get("dst")
            if src is not None and dst is not None:
                edge_strs.append(f"{src}->{dst}")
        edge_strs.sort()
        # Return None if no valid edges were found despite edges list existing
        if not edge_strs:
            return None
        return "|".join(edge_strs)
    blocks = cfg.get("blocks", [])
    if blocks:
        block_addrs = sorted(block.get("offset", 0) for block in blocks)
        return "|".join(str(addr) for addr in block_addrs)
    return str(func_offset)


def calculate_function_ccbhash(
    analyzer: CcbHashHost, func_offset: int, func_name: str, logger: logging.Logger
) -> str | None:
    try:
        cfg_data = (
            analyzer.adapter.get_cfg(func_offset)
            if analyzer.adapter is not None and hasattr(analyzer.adapter, "get_cfg")
            else analyzer._cmd_list("agj")
        )
        if not cfg_data or len(cfg_data) == 0:
            logger.debug("No CFG data found for function %s", func_name)
            return None
        cfg = cfg_data[0]
        canonical = analyzer._build_canonical_representation(cfg, func_offset)
        if not canonical:
            return None
        ccbhash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        logger.debug("CCBHash calculated for %s: %s...", func_name, ccbhash[:16])
        return ccbhash
    except Exception as exc:
        logger.debug("Error calculating CCBHash for function %s: %s", func_name, exc)
        return None


def find_similar_functions(
    function_hashes: dict[str, dict[str, Any]], logger: logging.Logger
) -> list[dict[str, Any]]:
    try:
        hash_groups: dict[str, list[str]] = {}
        for func_name, func_data in function_hashes.items():
            ccbhash = func_data["ccbhash"]
            hash_groups.setdefault(ccbhash, []).append(clean_function_name(func_name))
        similar_groups = [
            {"ccbhash": ccbhash, "functions": func_names, "count": len(func_names)}
            for ccbhash, func_names in hash_groups.items()
            if len(func_names) > 1
        ]
        similar_groups.sort(key=lambda item: cast(int, item["count"]), reverse=True)
        return similar_groups
    except Exception as exc:
        logger.error("Error finding similar functions: %s", exc)
        return []


def calculate_binary_ccbhash(
    function_hashes: dict[str, dict[str, Any]], logger: logging.Logger
) -> str | None:
    try:
        if not function_hashes:
            return None
        all_hashes = sorted([func_data["ccbhash"] for func_data in function_hashes.values()])
        combined = "|".join(all_hashes)
        binary_ccbhash = hashlib.sha256(combined.encode("utf-8")).hexdigest()
        logger.debug("Binary CCBHash calculated: %s...", binary_ccbhash[:16])
        return binary_ccbhash
    except Exception as exc:
        logger.error("Error calculating binary CCBHash: %s", exc)
        return None
