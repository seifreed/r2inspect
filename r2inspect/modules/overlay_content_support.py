"""Overlay content analysis helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def analyze_overlay_content(
    *,
    cmdj: Callable[[str, Any], Any],
    result: dict[str, Any],
    offset: int,
    size: int,
    logger: Any,
    calculate_entropy_fn: Callable[[list[int]], float],
    calculate_hashes_fn: Callable[[bytes], dict[str, str]],
    check_patterns_fn: Callable[[list[int]], list[dict[str, Any]]],
    determine_overlay_type_fn: Callable[[list[dict[str, Any]], list[int]], str],
    extract_strings_fn: Callable[[list[int], int], list[str]],
    check_file_signatures_fn: Callable[[list[int]], list[dict[str, Any]]],
) -> None:
    try:
        read_size = min(size, 65536)
        overlay_data = cmdj(f"pxj {read_size} @ {offset}", [])

        if not overlay_data:
            return

        result["overlay_entropy"] = calculate_entropy_fn(overlay_data)

        try:
            overlay_bytes = bytes(overlay_data[: min(len(overlay_data), read_size)])
            result["overlay_hashes"] = calculate_hashes_fn(overlay_bytes)
        except Exception as exc:
            logger.debug("Error calculating overlay hashes: %s", exc)
            result["overlay_hashes"] = {}

        patterns = check_patterns_fn(overlay_data)
        result["patterns_found"] = patterns
        result["potential_type"] = determine_overlay_type_fn(patterns, overlay_data)
        result["extracted_strings"] = extract_strings_fn(overlay_data, 6)[:20]

        signatures = check_file_signatures_fn(overlay_data)
        if signatures:
            result["embedded_files"] = signatures

    except Exception as exc:
        logger.error("Error analyzing overlay content: %s", exc)
