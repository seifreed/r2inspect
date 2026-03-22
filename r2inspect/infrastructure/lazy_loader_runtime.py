#!/usr/bin/env python3
"""Runtime operations for the lazy analyzer loader."""

from __future__ import annotations

import importlib
import time
from typing import Any, cast

from .lazy_loader_models import LazyAnalyzerSpec


def register_analyzer(
    loader: Any,
    name: str,
    module_path: str,
    class_name: str,
    category: str | None,
    formats: set[str] | None,
    metadata: dict[str, Any] | None,
    *,
    logger: Any,
) -> None:
    if not name:
        raise ValueError("Analyzer name cannot be empty")
    if not module_path or not class_name:
        raise ValueError("Module path and class name are required")

    existing = loader._registry.get(name)
    if existing and (existing.module_path != module_path or existing.class_name != class_name):
        logger.warning(
            f"Analyzer '{name}' already registered with different path. "
            f"Overwriting: {existing.module_path}.{existing.class_name} "
            f"-> {module_path}.{class_name}"
        )

    loader._registry[name] = LazyAnalyzerSpec(
        module_path=module_path,
        class_name=class_name,
        category=category,
        formats=formats or set(),
        metadata=metadata or {},
    )
    logger.debug("Registered lazy analyzer: %s -> %s.%s", name, module_path, class_name)


def load_analyzer_class(loader: Any, name: str, *, logger: Any) -> type[Any] | None:
    spec = loader._registry.get(name)
    if spec is None:
        logger.debug("Analyzer '%s' not found in lazy loader registry", name)
        return None

    # Check cache under lock to prevent duplicate imports
    with loader._cache_lock:
        cached = loader._cache.get(name)
        if cached is not None:
            loader._stats["cache_hits"] += 1
            return cast(type[Any] | None, cached)

    loader._stats["cache_misses"] += 1
    try:
        start = time.perf_counter()
        module = importlib.import_module(spec.module_path)
        analyzer_class = cast(type[Any], getattr(module, spec.class_name))
        load_time_ms = (time.perf_counter() - start) * 1000
        with loader._cache_lock:
            # Double-check: another thread may have loaded while we imported
            if name in loader._cache:
                return cast(type[Any] | None, loader._cache[name])
            loader._cache[name] = analyzer_class
            loader._stats["load_times"][name] = load_time_ms
            loader._stats["load_count"] += 1
        logger.debug(
            f"Loaded analyzer '{name}' from {spec.module_path}.{spec.class_name} "
            f"in {load_time_ms:.2f}ms"
        )
        return analyzer_class
    except ImportError as exc:
        with loader._cache_lock:
            loader._stats["failed_loads"] += 1
        logger.error(f"Failed to import module '{spec.module_path}' for analyzer '{name}': {exc}")
        raise
    except AttributeError as exc:
        with loader._cache_lock:
            loader._stats["failed_loads"] += 1
        logger.error(
            f"Class '{spec.class_name}' not found in module '{spec.module_path}' "
            f"for analyzer '{name}': {exc}"
        )
        raise


def unload_analyzer(loader: Any, name: str, *, logger: Any) -> bool:
    if name not in loader._cache:
        return False
    with loader._cache_lock:
        del loader._cache[name]
    logger.debug("Unloaded analyzer '%s' from cache", name)
    return True


def unregister_analyzer(loader: Any, name: str, *, logger: Any) -> bool:
    removed = False
    if name in loader._registry:
        del loader._registry[name]
        removed = True
    if name in loader._cache:
        with loader._cache_lock:
            del loader._cache[name]
        removed = True
    if removed:
        logger.debug("Unregistered analyzer '%s'", name)
    return removed


def preload_analyzers(loader: Any, *names: str, logger: Any) -> dict[str, bool]:
    results: dict[str, bool] = {}
    for name in names:
        try:
            loader.get_analyzer_class(name)
            results[name] = True
        except (ImportError, AttributeError) as exc:
            logger.error("Failed to preload analyzer '%s': %s", name, exc)
            results[name] = False
    return results


def preload_category(loader: Any, category: str, *, logger: Any) -> dict[str, bool]:
    names = [name for name, spec in loader._registry.items() if spec.category == category]
    return preload_analyzers(loader, *names, logger=logger)


def clear_cache(loader: Any, *, logger: Any) -> int:
    with loader._cache_lock:
        count = len(loader._cache)
        loader._cache.clear()
    logger.debug("Cleared %s analyzers from cache", count)
    return count


def list_registered(loader: Any) -> dict[str, dict[str, Any]]:
    return {
        name: {
            "module_path": spec.module_path,
            "class_name": spec.class_name,
            "category": spec.category,
            "formats": list(spec.formats),
            "loaded": loader.is_loaded(name),
            "metadata": spec.metadata,
        }
        for name, spec in loader._registry.items()
    }
