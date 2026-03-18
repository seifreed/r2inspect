"""Bloom serialization and similarity helpers for Binbloom analysis."""

from __future__ import annotations

import base64
import json
from typing import Any


def calculate_bloom_stats(
    analyzer: Any,
    function_blooms: dict[str, Any],
    capacity: int,
    error_rate: float,
    logger: Any,
) -> dict[str, Any]:
    try:
        if not function_blooms:
            return {}

        total_bits_set, total_capacity = analyzer._accumulate_bloom_bits(function_blooms)
        return {
            "total_filters": len(function_blooms),
            "configured_capacity": capacity,
            "configured_error_rate": error_rate,
            "average_fill_rate": ((total_bits_set / total_capacity) if total_capacity > 0 else 0.0),
        }
    except Exception as exc:
        logger.error("Error calculating Bloom stats: %s", exc)
        return {}


def compare_bloom_filters(analyzer: Any, bloom1: Any, bloom2: Any, logger: Any) -> float:
    try:
        bits_1_raw = analyzer._get_bloom_bits(bloom1)
        bits_2_raw = analyzer._get_bloom_bits(bloom2)
        if bits_1_raw is None or bits_2_raw is None:
            return 0.0

        bits1 = {i for i, bit in enumerate(bits_1_raw) if bit}
        bits2 = {i for i, bit in enumerate(bits_2_raw) if bit}

        if not bits1 and not bits2:
            return 1.0
        if not bits1 or not bits2:
            return 0.0

        intersection = len(bits1.intersection(bits2))
        union = len(bits1.union(bits2))
        return intersection / union if union > 0 else 0.0
    except Exception as exc:
        logger.error("Error comparing Bloom filters: %s", exc)
        return 0.0


def deserialize_bloom(bloom_b64: str, bloom_filter_class: Any, logger: Any) -> Any | None:
    try:
        json_bytes = base64.b64decode(bloom_b64.encode("utf-8"))
        data = json.loads(json_bytes.decode("utf-8"))

        if not isinstance(data, dict):
            logger.error("Deserialization failed: data is not a dictionary")
            return None

        version = data.get("version")
        if version != 1:
            logger.error("Deserialization failed: unsupported version %s", version)
            return None

        try:
            error_rate = float(data["error_rate"])
            capacity = int(data["capacity"])
            count = int(data["count"])
            bitarray_list = data["bitarray"]
        except (KeyError, TypeError, ValueError) as exc:
            logger.error("Deserialization failed: invalid parameter - %s", exc)
            return None

        if not (0.0 < error_rate < 1.0):
            logger.error("Deserialization failed: invalid error_rate %s", error_rate)
            return None
        if not (1 <= capacity <= 1000000):
            logger.error("Deserialization failed: invalid capacity %s", capacity)
            return None
        if not (0 <= count <= capacity):
            logger.error("Deserialization failed: invalid count %s", count)
            return None
        if not isinstance(bitarray_list, list):
            logger.error("Deserialization failed: bitarray is not a list")
            return None

        bloom_filter = bloom_filter_class(capacity=capacity, error_rate=error_rate)

        from bitarray import bitarray

        bloom_filter.bitarray = bitarray(bitarray_list)
        bloom_filter.count = count
        logger.debug(
            "Successfully deserialized Bloom filter (capacity=%s, count=%s)",
            capacity,
            count,
        )
        return bloom_filter
    except json.JSONDecodeError as exc:
        logger.error("Deserialization failed: invalid JSON - %s", exc)
        return None
    except Exception as exc:
        logger.error("Deserialization failed: %s", exc)
        return None
