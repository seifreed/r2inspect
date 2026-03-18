#!/usr/bin/env python3
"""Lazy analyzer loader facade."""

import logging
import threading
from typing import Any

from .lazy_loader_models import LazyAnalyzerSpec, LoaderStats, init_loader_stats
from .lazy_loader_runtime import (
    clear_cache as _clear_cache,
    list_registered as _list_registered,
    load_analyzer_class as _load_analyzer_class,
    preload_analyzers as _preload_analyzers,
    preload_category as _preload_category,
    register_analyzer as _register_analyzer,
    unregister_analyzer as _unregister_analyzer,
    unload_analyzer as _unload_analyzer,
)
from .lazy_loader_stats import build_stats as _build_stats

logger = logging.getLogger(__name__)


class LazyAnalyzerLoader:
    """Lazy loader for analyzer classes."""

    def __init__(self) -> None:
        self._registry: dict[str, LazyAnalyzerSpec] = {}
        self._cache: dict[str, type[Any]] = {}
        self._cache_lock = threading.Lock()
        self._stats = init_loader_stats()

    def register(
        self,
        name: str,
        module_path: str,
        class_name: str,
        category: str | None = None,
        formats: set[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        _register_analyzer(
            self,
            name,
            module_path,
            class_name,
            category,
            formats,
            metadata,
            logger=logger,
        )

    def get_analyzer_class(self, name: str) -> type[Any] | None:
        return _load_analyzer_class(self, name, logger=logger)

    def is_loaded(self, name: str) -> bool:
        return name in self._cache

    def is_registered(self, name: str) -> bool:
        return name in self._registry

    def unload(self, name: str) -> bool:
        return _unload_analyzer(self, name, logger=logger)

    def unregister(self, name: str) -> bool:
        return _unregister_analyzer(self, name, logger=logger)

    def preload(self, *names: str) -> dict[str, bool]:
        return _preload_analyzers(self, *names, logger=logger)

    def preload_category(self, category: str) -> dict[str, bool]:
        return _preload_category(self, category, logger=logger)

    def get_stats(self) -> dict[str, Any]:
        return _build_stats(self)

    def clear_cache(self) -> int:
        return _clear_cache(self, logger=logger)

    def list_registered(self) -> dict[str, dict[str, Any]]:
        return _list_registered(self)

    def __len__(self) -> int:
        return len(self._registry)

    def __contains__(self, name: str) -> bool:
        return name in self._registry

    def __repr__(self) -> str:
        return f"LazyAnalyzerLoader(registered={len(self._registry)}, loaded={len(self._cache)})"


_global_lazy_loader: LazyAnalyzerLoader | None = None
_global_loader_lock = threading.Lock()


def get_global_lazy_loader() -> LazyAnalyzerLoader:
    global _global_lazy_loader
    if _global_lazy_loader is None:
        with _global_loader_lock:
            if _global_lazy_loader is None:
                _global_lazy_loader = LazyAnalyzerLoader()
    return _global_lazy_loader


_init_loader_stats = init_loader_stats


__all__ = [
    "LazyAnalyzerLoader",
    "LazyAnalyzerSpec",
    "LoaderStats",
    "_init_loader_stats",
    "init_loader_stats",
    "get_global_lazy_loader",
]
