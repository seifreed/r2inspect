"""Helpers for CCBHash function and binary analysis."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterable
from typing import Any, Protocol, cast

from ..abstractions.coercion_support import coerce_int
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
    if isinstance(functions, list):
        function_source = functions
    elif isinstance(functions, (dict, str, bytes)) or not isinstance(functions, Iterable):
        return function_hashes, analyzed_count
    else:
        function_source = list(functions)
    for func in function_source:
        if not isinstance(func, dict):
            continue
        func_offset = coerce_int(func.get("addr"))
        if func_offset <= 0:
            continue
        func_name_value = func.get("name")
        func_name = (
            func_name_value
            if isinstance(func_name_value, str) and func_name_value
            else f"func_{func_offset}"
        )
        ccbhash = analyzer._calculate_function_ccbhash(func_offset, func_name)
        if ccbhash:
            function_hashes[func_name] = {
                "ccbhash": ccbhash,
                "addr": func_offset,
                "size": coerce_int(func.get("size", 0)),
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


def _edges_canonical(edges: list[Any]) -> str | None:
    edge_strs = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        src = edge.get("src")
        dst = edge.get("dst")
        if src is not None and dst is not None:
            edge_strs.append(f"{src}->{dst}")
    edge_strs.sort()
    # No valid edges despite a non-empty edges list collapses to None.
    if not edge_strs:
        return None
    return "|".join(edge_strs)


def _blocks_canonical(blocks: list[Any]) -> str:
    # r2 basic blocks (agj/afbj) carry the address as "addr", not "offset",
    # so reading only "offset" read 0 for every block and collapsed edgeless
    # functions to a constant "0" canonical form.
    block_addrs = sorted(
        coerce_int(block.get("addr") or block.get("offset", 0))
        for block in blocks
        if isinstance(block, dict)
    )
    return "|".join(str(addr) for addr in block_addrs)


def build_canonical_representation(cfg: dict[str, Any], func_offset: int) -> str | None:
    if not isinstance(cfg, dict):
        return str(func_offset)
    edges = cfg.get("edges", [])
    if isinstance(edges, list) and edges:
        return _edges_canonical(edges)
    blocks = cfg.get("blocks", [])
    if isinstance(blocks, list) and blocks:
        return _blocks_canonical(blocks)
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
        if isinstance(cfg_data, list):
            cfg_source = cfg_data
        elif isinstance(cfg_data, (dict, str, bytes)) or not isinstance(cfg_data, Iterable):
            return None
        else:
            cfg_source = list(cfg_data)
        if not cfg_source:
            logger.debug("No CFG data found for function %s", func_name)
            return None
        cfg = cfg_source[0]
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
            if not isinstance(func_data, dict):
                continue
            ccbhash = func_data.get("ccbhash")
            if not isinstance(ccbhash, str) or not ccbhash:
                continue
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
        all_hashes = sorted(
            func_data["ccbhash"]
            for func_data in function_hashes.values()
            if isinstance(func_data, dict)
            and isinstance(func_data.get("ccbhash"), str)
            and func_data["ccbhash"]
        )
        if not all_hashes:
            return None
        combined = "|".join(all_hashes)
        binary_ccbhash = hashlib.sha256(combined.encode("utf-8")).hexdigest()
        logger.debug("Binary CCBHash calculated: %s...", binary_ccbhash[:16])
        return binary_ccbhash
    except Exception as exc:
        logger.error("Error calculating binary CCBHash: %s", exc)
        return None
