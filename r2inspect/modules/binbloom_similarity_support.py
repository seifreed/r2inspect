"""Bloom serialization and similarity helpers for Binbloom analysis."""

from __future__ import annotations

import base64
import json
import logging
from collections.abc import Iterable
from typing import Any

from ..domain.services.binbloom import (
    calculate_bloom_similarity,
    calculate_bloom_stats as _calculate_bloom_stats_domain,
)


def calculate_bloom_stats(
    function_blooms: dict[str, Any],
    capacity: int,
    error_rate: float,
    logger: logging.Logger,
) -> dict[str, Any]:
    try:
        if not function_blooms:
            return {}

        return _calculate_bloom_stats_domain(
            function_blooms, capacity=capacity, error_rate=error_rate
        )
    except Exception as exc:
        logger.error("Error calculating Bloom stats: %s", exc)
        return {}


def compare_bloom_filters(bloom1: Any, bloom2: Any, logger: logging.Logger) -> float:
    try:
        return calculate_bloom_similarity(bloom1, bloom2)
    except Exception as exc:
        logger.error("Error comparing Bloom filters: %s", exc)
        return 0.0


def deserialize_bloom(
    bloom_b64: str, bloom_filter_class: Any, logger: logging.Logger
) -> Any | None:
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
        if isinstance(bitarray_list, list):
            bitarray_source = bitarray_list
        elif isinstance(bitarray_list, (dict, str, bytes)) or not isinstance(
            bitarray_list, Iterable
        ):
            logger.error("Deserialization failed: bitarray is not iterable")
            return None
        else:
            bitarray_source = list(bitarray_list)

        bloom_filter = bloom_filter_class(capacity=capacity, error_rate=error_rate)

        from bitarray import bitarray

        bloom_filter.bitarray = bitarray(bitarray_source)
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
