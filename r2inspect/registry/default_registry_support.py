"""Operational helpers for the public default registry facade."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .analyzer_registry import AnalyzerMetadata, AnalyzerRegistry
from .default_registry_data import ANALYZERS


def create_default_registry_impl(
    *, entry_points_fn: Callable[[], Any] | None = None
) -> AnalyzerRegistry:
    registry = AnalyzerRegistry()
    for analyzer in ANALYZERS:
        registry.register(**analyzer)

    try:
        if entry_points_fn is None:
            registry.load_entry_points("r2inspect.analyzers")
        else:
            registry.load_entry_points("r2inspect.analyzers", entry_points_fn)
    except Exception:
        pass
    return registry


def filter_registry_impl(
    predicate: Callable[[AnalyzerMetadata], bool],
    create_registry: Callable[[], AnalyzerRegistry],
) -> AnalyzerRegistry:
    # Drop non-matching analyzers from a fresh full registry rather than copying
    # metadata into a blank one. Under lazy loading the metadata.analyzer_class
    # is a LazyPlaceholder and the real module_path/class_name live only in the
    # registry's lazy loader; re-registering by analyzer_class would lose them
    # and make get_analyzer_class return the placeholder. Mutating the original
    # registry preserves its lazy loader so kept analyzers still resolve.
    registry = create_registry()
    for name in list(registry):
        metadata = registry.get_metadata(name)
        if not metadata or not predicate(metadata):
            registry.unregister(name)

    return registry
