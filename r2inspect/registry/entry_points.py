#!/usr/bin/env python3
"""Entry point loading for analyzers."""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable
from importlib.metadata import entry_points
from typing import TYPE_CHECKING, Any

from .categories import AnalyzerCategory
from .metadata import AnalyzerSpec

if TYPE_CHECKING:
    from .analyzer_registry import AnalyzerRegistry


class EntryPointLoader:
    """Load analyzers registered via Python entry points."""

    def __init__(
        self, registry: AnalyzerRegistry, entry_points_fn: Callable[[], Any] | None = None
    ) -> None:
        self._registry = registry
        self._entry_points_fn = entry_points_fn or entry_points

    def load(self, group: str = "r2inspect.analyzers") -> int:
        loaded = 0
        eps_group = self._get_entry_points_group(group)
        if not eps_group:
            return loaded
        for ep in eps_group:
            loaded += self._handle_entry_point(ep)
        return loaded

    def _get_entry_points_group(self, group: str) -> list[Any]:
        try:
            return list(self._entry_points_fn().select(group=group))
        except Exception as exc:
            logging.getLogger(__name__).exception(
                "Error loading entry points for group '%s': %s", group, exc
            )
            return []

    def _handle_entry_point(self, ep: Any) -> int:
        try:
            obj = ep.load()
        except Exception as exc:
            logging.getLogger(__name__).warning(
                f"Failed to load entry point '{getattr(ep, 'name', '?')}': {exc}"
            )
            return 0

        if inspect.isclass(obj):
            return self._register_entry_point_class(ep, obj)

        if callable(obj):
            return self._register_entry_point_callable(ep, obj)

        return 0

    def _register_entry_point_callable(self, ep: Any, obj: Any) -> int:
        try:
            obj(self._registry)
            return 1
        except Exception as exc:
            logging.getLogger(__name__).warning(f"Entry point '{ep.name}' callable failed: {exc}")
            return 0

    def _register_entry_point_class(self, ep: Any, obj: Any) -> int:
        try:
            spec = getattr(obj, "spec", None)
            if spec is not None:
                if not isinstance(spec, AnalyzerSpec):
                    raise TypeError("spec must be an AnalyzerSpec")
                self._registry.register(
                    name=spec.id,
                    analyzer_class=obj,
                    category=spec.category,
                    file_formats=set(spec.formats),
                    required=spec.required,
                    dependencies=set(spec.dependencies),
                    description=spec.description,
                    version=spec.version,
                    architectures=set(spec.architectures),
                    output_schema=spec.output_schema,
                    auto_extract=False,
                )
                return 1
            name = self._derive_entry_point_name(ep, obj)
            self._registry.register(
                name=name,
                analyzer_class=obj,
                category=AnalyzerCategory.METADATA,
                file_formats=set(),
                required=False,
                auto_extract=False,
            )
            return 1
        except Exception as exc:
            logging.getLogger(__name__).warning(
                f"Failed to register entry point '{ep.name}': {exc}"
            )
            return 0

    def _derive_entry_point_name(self, ep: Any, obj: Any) -> str:
        # Legacy entry points must provide metadata through the entry-point
        # name; discovery must never construct an analyzer just to inspect it.
        return str(getattr(ep, "name", None) or getattr(obj, "__name__", "analyzer"))
