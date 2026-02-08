#!/usr/bin/env python3
"""Helpers for LazyAnalyzerLoader statistics and reporting."""

from __future__ import annotations

from typing import Any


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
    """Print formatted stats for a LazyAnalyzerLoader-like object."""
    stats = build_stats(loader)

    print("\nLazy Loader Statistics")
    print("=" * 50)
    print(f"Registered analyzers: {stats['registered']}")
    print(f"Loaded analyzers:     {stats['loaded']}")
    print(f"Unloaded analyzers:   {stats['unloaded']}")
    print(f"Load count:           {stats['load_count']}")
    print(f"Cache hits:           {stats['cache_hits']}")
    print(f"Cache misses:         {stats['cache_misses']}")
    print(f"Failed loads:         {stats['failed_loads']}")
    print(f"Cache hit rate:       {stats['cache_hit_rate']:.1%}")
    print(f"Lazy ratio:           {stats['lazy_ratio']:.1%}")

    if stats["load_times"]:
        print("\nLoad Times (ms):")
        for name, time_ms in sorted(stats["load_times"].items(), key=lambda x: x[1], reverse=True):
            print(f"  {name:20s}: {time_ms:6.2f} ms")
