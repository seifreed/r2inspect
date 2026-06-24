"""Overlay content analysis helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..abstractions.coercion_support import coerce_int_or_none, coerce_list, is_byte_list


def _load_overlay_data(
    cmdj: Callable[[str, Any], Any], offset: int, size: int
) -> tuple[list[int], int] | None:
    read_offset = coerce_int_or_none(offset)
    read_total = coerce_int_or_none(size)
    if read_offset is None or read_total is None:
        return None
    read_size = min(read_total, 65536)
    overlay_data = cmdj(f"pxj {read_size} @ {read_offset}", [])
    if isinstance(overlay_data, (dict, str, bytes)):
        return None
    try:
        overlay_data = list(overlay_data)
    except TypeError:
        return None
    if not overlay_data or not is_byte_list(overlay_data):
        return None
    return overlay_data, read_size


def _store_overlay_hashes(
    result: dict[str, Any],
    overlay_data: list[int],
    read_size: int,
    calculate_hashes_fn: Callable[[bytes], dict[str, str]],
    logger: Any,
) -> None:
    try:
        overlay_bytes = bytes(overlay_data[: min(len(overlay_data), read_size)])
        result["overlay_hashes"] = calculate_hashes_fn(overlay_bytes)
    except Exception as exc:
        logger.debug("Error calculating overlay hashes: %s", exc)
        result["overlay_hashes"] = {}


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
        loaded = _load_overlay_data(cmdj, offset, size)
        if loaded is None:
            return
        overlay_data, read_size = loaded

        result["overlay_entropy"] = calculate_entropy_fn(overlay_data)
        _store_overlay_hashes(result, overlay_data, read_size, calculate_hashes_fn, logger)

        patterns = check_patterns_fn(overlay_data)
        if not isinstance(patterns, list):
            patterns = []
        result["patterns_found"] = patterns
        result["potential_type"] = determine_overlay_type_fn(patterns, overlay_data)
        extracted_strings = extract_strings_fn(overlay_data, 6)
        if not isinstance(extracted_strings, list):
            extracted_strings = []
        result["extracted_strings"] = extracted_strings[:20]

        signatures = coerce_list(check_file_signatures_fn(overlay_data))
        if signatures:
            result["embedded_files"] = signatures

    except Exception as exc:
        logger.error("Error analyzing overlay content: %s", exc)
