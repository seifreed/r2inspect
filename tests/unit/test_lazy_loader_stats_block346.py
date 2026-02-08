from __future__ import annotations

import io
import sys

from r2inspect.lazy_loader_stats import build_stats, print_stats


class DummyLoader:
    def __init__(self) -> None:
        self._stats = {
            "cache_hits": 2,
            "cache_misses": 3,
            "load_count": 1,
            "failed_loads": 1,
            "load_times": {"a": 2.0, "b": 1.0},
        }
        self._registry = {"a": object(), "b": object(), "c": object()}
        self._cache = {"a": object()}


def test_build_stats_and_print() -> None:
    loader = DummyLoader()
    stats = build_stats(loader)

    assert stats["registered"] == 3
    assert stats["loaded"] == 1
    assert stats["unloaded"] == 2
    assert stats["cache_hits"] == 2
    assert stats["cache_misses"] == 3
    assert stats["failed_loads"] == 1
    assert stats["cache_hit_rate"] > 0
    assert stats["lazy_ratio"] > 0

    buffer = io.StringIO()
    original_stdout = sys.stdout
    try:
        sys.stdout = buffer
        print_stats(loader)
    finally:
        sys.stdout = original_stdout

    output = buffer.getvalue()
    assert "Lazy Loader Statistics" in output
    assert "Load Times" in output


def test_build_stats_no_accesses() -> None:
    loader = DummyLoader()
    loader._stats["cache_hits"] = 0
    loader._stats["cache_misses"] = 0
    loader._registry = {}
    loader._cache = {}

    stats = build_stats(loader)
    assert stats["cache_hit_rate"] == 0.0
    assert stats["lazy_ratio"] == 0.0
