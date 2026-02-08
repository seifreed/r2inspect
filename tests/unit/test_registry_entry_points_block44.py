from __future__ import annotations

import importlib

import pytest

from r2inspect.registry.analyzer_registry import AnalyzerRegistry


def test_entry_points_noop(monkeypatch):
    registry = AnalyzerRegistry(lazy_loading=False)

    def _fake_entry_points():
        return {}

    monkeypatch.setattr("r2inspect.registry.analyzer_registry.entry_points", _fake_entry_points)
    loaded = registry.load_entry_points(group="missing")
    assert loaded == 0
