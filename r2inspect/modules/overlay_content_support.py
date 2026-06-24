"""Overlay content analysis helpers."""

from __future__ import annotations

from collections.abc import Iterable
from collections.abc import Callable
from typing import Any

from ..abstractions.coercion_support import coerce_int_or_none, is_byte_list


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
        read_offset = coerce_int_or_none(offset)
        read_total = coerce_int_or_none(size)
        if read_offset is None or read_total is None:
            return
        read_size = min(read_total, 65536)
        overlay_data = cmdj(f"pxj {read_size} @ {read_offset}", [])

        if isinstance(overlay_data, (dict, str, bytes)):
            return
        try:
            overlay_data = list(overlay_data)
        except TypeError:
            return
        if not overlay_data or not is_byte_list(overlay_data):
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
