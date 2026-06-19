"""Overlay content analysis helpers."""

from __future__ import annotations

from collections.abc import Iterable
from collections.abc import Callable
from typing import Any


def _to_int(value: Any) -> int | None:
    try:
        if isinstance(value, str):
            return int(value, 0)
        return int(value or 0)
    except (TypeError, ValueError):
        return None


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
        offset = _to_int(offset)
        size = _to_int(size)
        if offset is None or size is None:
            return
        read_size = min(size, 65536)
        overlay_data = cmdj(f"pxj {read_size} @ {offset}", [])

        if isinstance(overlay_data, (dict, str, bytes)):
            return
        try:
            overlay_data = list(overlay_data)
        except TypeError:
            return
        if (
            not overlay_data
            or not all(isinstance(value, int) and 0 <= value <= 0xFF for value in overlay_data)
        ):
            return

        result["overlay_entropy"] = calculate_entropy_fn(overlay_data)

        try:
            overlay_bytes = bytes(overlay_data[: min(len(overlay_data), read_size)])
            result["overlay_hashes"] = calculate_hashes_fn(overlay_bytes)
        except Exception as exc:
            logger.debug("Error calculating overlay hashes: %s", exc)
            result["overlay_hashes"] = {}

        patterns = check_patterns_fn(overlay_data)
        if not isinstance(patterns, list):
            patterns = []
        result["patterns_found"] = patterns
        result["potential_type"] = determine_overlay_type_fn(patterns, overlay_data)
        extracted_strings = extract_strings_fn(overlay_data, 6)
        if not isinstance(extracted_strings, list):
            extracted_strings = []
        result["extracted_strings"] = extracted_strings[:20]

        signatures = check_file_signatures_fn(overlay_data)
        if isinstance(signatures, list):
            normalized_signatures = signatures
        elif isinstance(signatures, (dict, str, bytes)) or not isinstance(signatures, Iterable):
            normalized_signatures = []
        else:
            normalized_signatures = list(signatures)
        if normalized_signatures:
            result["embedded_files"] = normalized_signatures

    except Exception as exc:
        logger.error("Error analyzing overlay content: %s", exc)
