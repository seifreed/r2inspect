#!/usr/bin/env python3
"""Shared models for the lazy analyzer loader."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TypedDict


class LoaderStats(TypedDict):
    load_count: int
    cache_hits: int
    cache_misses: int
    failed_loads: int
    load_times: dict[str, float]


def init_loader_stats() -> LoaderStats:
    return {
        "load_count": 0,
        "cache_hits": 0,
        "cache_misses": 0,
        "failed_loads": 0,
        "load_times": {},
    }


@dataclass(frozen=True)
class LazyAnalyzerSpec:
    """Registration metadata for a lazy analyzer."""

    module_path: str
    class_name: str
    category: str | None = None
    formats: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)
