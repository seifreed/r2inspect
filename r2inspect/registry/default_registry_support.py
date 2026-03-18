"""Operational helpers for the public default registry facade."""

from __future__ import annotations

from collections.abc import Callable

from ..infrastructure.logging import get_logger
from .analyzer_registry import AnalyzerMetadata, AnalyzerRegistry
from .default_registry_data import ANALYZERS

logger = get_logger(__name__)


def create_default_registry_impl() -> AnalyzerRegistry:
    registry = AnalyzerRegistry()
    for analyzer in ANALYZERS:
        registry.register(**analyzer)

    try:
        registry.load_entry_points()
    except Exception as exc:
        logger.debug("Failed to load entry points: %s", exc)

    return registry


def filter_registry_impl(
    predicate: Callable[[AnalyzerMetadata], bool],
    create_registry: Callable[[], AnalyzerRegistry],
) -> AnalyzerRegistry:
    default_registry = create_registry()
    filtered = AnalyzerRegistry()

    for name in default_registry:
        metadata = default_registry.get_metadata(name)
        if metadata and predicate(metadata):
            filtered.register(
                name=metadata.name,
                analyzer_class=metadata.analyzer_class,
                category=metadata.category,
                file_formats=metadata.file_formats,
                required=metadata.required,
                dependencies=metadata.dependencies,
                description=metadata.description,
            )

    return filtered
