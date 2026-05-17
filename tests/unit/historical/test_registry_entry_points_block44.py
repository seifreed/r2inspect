from __future__ import annotations

from r2inspect.registry.analyzer_registry import AnalyzerRegistry


def test_entry_points_noop():
    registry = AnalyzerRegistry(lazy_loading=False)

    def _fake_entry_points():
        return {}

    loaded = registry.load_entry_points(group="missing", entry_points_fn=_fake_entry_points)
    assert loaded == 0
