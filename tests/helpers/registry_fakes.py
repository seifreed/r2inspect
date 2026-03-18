from __future__ import annotations

from typing import Any

from r2inspect.registry.analyzer_registry import AnalyzerCategory, AnalyzerRegistry


def make_registry(entries: list[tuple[str, type[Any], AnalyzerCategory]]) -> AnalyzerRegistry:
    registry = AnalyzerRegistry(lazy_loading=False)
    for name, analyzer_class, category in entries:
        registry.register(name, analyzer_class, category)
    return registry
