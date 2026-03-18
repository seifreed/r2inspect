#!/usr/bin/env python3
"""Support logic for compiler detection."""

from __future__ import annotations

from typing import Any
from collections.abc import Callable


def detect_file_format(file_info: dict[str, Any], *, logger: Any) -> str:
    try:
        if "bin" not in file_info:
            return "Unknown"
        format_info = str(file_info["bin"].get("class", "")).upper()
        if "PE" in format_info:
            return "PE"
        if "ELF" in format_info:
            return "ELF"
        if "MACH" in format_info:
            return "Mach-O"
        return "Unknown"
    except Exception as exc:
        logger.debug("Error detecting file format: %s", exc)
        return "Unknown"


def apply_rich_header_detection(
    detector: Any,
    results: dict[str, Any],
    *,
    map_msvc_version: Callable[[str], str],
    logger: Any,
) -> bool:
    rich_header = detector._analyze_rich_header()
    results["rich_header_info"] = rich_header
    if not (rich_header.get("available") and rich_header.get("compilers")):
        return False

    for compiler_entry in rich_header["compilers"]:
        compiler_name = compiler_entry.get("compiler_name", "")
        if "MSVC" not in compiler_name and "Utc" not in compiler_name:
            continue
        results["detected"] = True
        results["compiler"] = "MSVC"
        results["confidence"] = 0.95
        results["version"] = map_msvc_version(compiler_name)
        results["details"] = {"detection_method": "Rich Header Analysis"}
        logger.debug("Detected %s %s from Rich Header", results["compiler"], results["version"])
        return True
    return False


def score_compilers(
    compiler_signatures: dict[str, Any],
    strings_data: list[str],
    imports_data: list[str],
    sections_data: list[str],
    symbols_data: list[str],
    *,
    calculate_score: Callable[
        [dict[str, list[str]], list[str], list[str], list[str], list[str]], float
    ],
) -> dict[str, float]:
    return {
        compiler_name: calculate_score(
            signatures,
            strings_data,
            imports_data,
            sections_data,
            symbols_data,
        )
        for compiler_name, signatures in compiler_signatures.items()
    }


def apply_best_compiler(
    results: dict[str, Any],
    compiler_scores: dict[str, float],
    strings_data: list[str],
    imports_data: list[str],
    file_format: str,
    *,
    detect_version: Callable[[str, list[str], list[str]], str],
    detection_method_fn: Callable[[str, float], str],
) -> None:
    if not compiler_scores:
        return
    best_compiler = max(compiler_scores, key=lambda k: compiler_scores[k])
    best_score = compiler_scores[best_compiler]
    if best_score <= 0.3:
        return
    results["detected"] = True
    results["compiler"] = best_compiler
    results["confidence"] = best_score
    results["version"] = detect_version(best_compiler, strings_data, imports_data)
    results["details"] = {
        "all_scores": compiler_scores,
        "file_format": file_format,
        "detection_method": detection_method_fn(best_compiler, best_score),
    }


def detect_compiler_version(
    compiler: str,
    strings_data: list[str],
    imports_data: list[str],
    *,
    detectors: dict[str, Callable[[list[str], list[str]], str]],
) -> str:
    detector = detectors.get(compiler)
    return detector(strings_data, imports_data) if detector else "Unknown"


def coerce_dict_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def analyze_rich_header(detector: Any, *, logger: Any) -> dict[str, Any]:
    try:
        from .rich_header_analyzer import RichHeaderAnalyzer

        file_info = detector._get_file_info()
        if "core" not in file_info:
            return {}
        filepath = file_info["core"].get("file", "")
        if not filepath:
            return {}
        return RichHeaderAnalyzer(detector.adapter, filepath).analyze()
    except Exception as exc:
        logger.error("Error analyzing Rich header: %s", exc)
        return {}
