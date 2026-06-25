#!/usr/bin/env python3
"""Support logic for compiler detection."""

from __future__ import annotations

from typing import Any
from collections.abc import Callable


def detect_file_format(file_info: dict[str, Any], *, logger: Any) -> str:
    try:
        bin_info = file_info.get("bin")
        if not isinstance(bin_info, dict):
            return "Unknown"
        format_info = str(bin_info.get("class", "")).upper()
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
    if not isinstance(rich_header, dict):
        rich_header = {}
    results["rich_header_info"] = rich_header
    if not (rich_header.get("available") and rich_header.get("compilers")):
        return False

    for compiler_entry in rich_header["compilers"]:
        if not isinstance(compiler_entry, dict):
            continue
        compiler_name = compiler_entry.get("compiler_name", "")
        if not isinstance(compiler_name, str):
            continue
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
    calculate_score: Callable[[dict[str, Any], list[str], list[str], list[str], list[str]], float],
) -> dict[str, float]:
    scores: dict[str, float] = {}
    for compiler_name, signatures in compiler_signatures.items():
        # Each compiler maps to a signature dict ({"strings": [...], "imports":
        # [...], ...}); calculate_score indexes those keys. Skipping dicts here
        # (as the old normalize-to-list logic did) silently zeroed every score.
        if not isinstance(signatures, dict):
            continue
        scores[compiler_name] = calculate_score(
            signatures,
            strings_data,
            imports_data,
            sections_data,
            symbols_data,
        )
    return scores


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
    if not isinstance(compiler_scores, dict) or not compiler_scores:
        return
    numeric_scores = {
        compiler_name: score
        for compiler_name, score in compiler_scores.items()
        if isinstance(score, (int, float))
    }
    if not numeric_scores:
        return
    best_compiler = max(numeric_scores, key=lambda k: numeric_scores[k])
    best_score = float(numeric_scores[best_compiler])
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


def analyze_rich_header(detector: Any, *, logger: Any) -> dict[str, Any]:
    try:
        from .rich_header_analyzer import RichHeaderAnalyzer

        file_info = detector._get_file_info()
        if not isinstance(file_info, dict):
            return {}
        core = file_info.get("core")
        if not isinstance(core, dict):
            return {}
        filepath = core.get("file", "")
        if not filepath:
            return {}
        return RichHeaderAnalyzer(detector.adapter, filepath).analyze()
    except Exception as exc:
        logger.error("Error analyzing Rich header: %s", exc)
        return {}
