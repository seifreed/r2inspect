#!/usr/bin/env python3
"""Helpers for LazyAnalyzerLoader statistics and reporting."""

from __future__ import annotations

from typing import Any

from .logging import get_logger

logger = get_logger(__name__)


def build_stats(loader: Any) -> dict[str, Any]:
    """Build stats for a LazyAnalyzerLoader-like object."""
    total_accesses = loader._stats["cache_hits"] + loader._stats["cache_misses"]
    cache_hit_rate = loader._stats["cache_hits"] / total_accesses if total_accesses > 0 else 0.0

    registered_count = len(loader._registry)
    loaded_count = len(loader._cache)
    lazy_ratio = 1 - (loaded_count / registered_count) if registered_count > 0 else 0.0

    return {
        "registered": registered_count,
        "loaded": loaded_count,
        "unloaded": registered_count - loaded_count,
        "load_count": loader._stats["load_count"],
        "cache_hits": loader._stats["cache_hits"],
        "cache_misses": loader._stats["cache_misses"],
        "failed_loads": loader._stats["failed_loads"],
        "cache_hit_rate": cache_hit_rate,
        "lazy_ratio": lazy_ratio,
        "load_times": loader._stats["load_times"].copy(),
    }


def print_stats(loader: Any) -> None:
    """Log formatted stats for a LazyAnalyzerLoader-like object."""
    stats = build_stats(loader)

    logger.info("Lazy Loader Statistics")
    logger.info("=" * 50)
    logger.info("Registered analyzers: %s", stats["registered"])
    logger.info("Loaded analyzers:     %s", stats["loaded"])
    logger.info("Unloaded analyzers:   %s", stats["unloaded"])
    logger.info("Load count:           %s", stats["load_count"])
    logger.info("Cache hits:           %s", stats["cache_hits"])
    logger.info("Cache misses:         %s", stats["cache_misses"])
    logger.info("Failed loads:         %s", stats["failed_loads"])
    logger.info("Cache hit rate:       %.1f%%", stats["cache_hit_rate"] * 100)
    logger.info("Lazy ratio:           %.1f%%", stats["lazy_ratio"] * 100)

    if stats["load_times"]:
        logger.info("Load Times (ms):")
        for name, time_ms in sorted(stats["load_times"].items(), key=lambda x: x[1], reverse=True):
            logger.info("  %-20s: %6.2f ms", name, time_ms)
