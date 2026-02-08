#!/usr/bin/env python3
"""
Lazy Analyzer Loader Module.

Provides lazy loading of analyzer classes to defer imports until first access.
"""

import importlib
import logging
import sys
import threading
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, TypedDict, cast

from .lazy_loader_stats import build_stats as _build_stats

logger = logging.getLogger(__name__)


class LoaderStats(TypedDict):
    load_count: int
    cache_hits: int
    cache_misses: int
    failed_loads: int
    load_times: dict[str, float]


def _init_loader_stats() -> LoaderStats:
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


class LazyAnalyzerLoader:
    """Lazy loader for analyzer classes."""

    def __init__(self) -> None:
        """
        Initialize lazy loader with empty registry.

        The loader maintains two data structures:
        - _registry: Maps analyzer names to registration metadata
        - _cache: Stores loaded analyzer classes for fast repeated access
        """
        self._registry: dict[str, LazyAnalyzerSpec] = {}
        self._cache: dict[str, type[Any]] = {}
        self._cache_lock = threading.Lock()

        # Statistics tracking for optimization analysis
        self._stats = _init_loader_stats()

    def register(
        self,
        name: str,
        module_path: str,
        class_name: str,
        category: str | None = None,
        formats: set[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Register an analyzer for lazy loading.

        This method only stores metadata about the analyzer - no import occurs.
        The analyzer module will be imported lazily when first accessed via
        get_analyzer_class().

        Args:
            name: Unique identifier for the analyzer
            module_path: Python module path (e.g., "r2inspect.modules.pe_analyzer")
            class_name: Class name within the module (e.g., "PEAnalyzer")
            category: Optional category for grouping (e.g., "format", "hashing")
            formats: Optional set of supported file formats (e.g., {"PE", "PE32"})
            metadata: Optional additional metadata dictionary

        Raises:
            ValueError: If name is empty or already registered with different path

        Example:
            >>> loader.register(
            ...     name="pe",
            ...     module_path="r2inspect.modules.pe_analyzer",
            ...     class_name="PEAnalyzer",
            ...     category="format",
            ...     formats={"PE", "PE32", "PE32+"}
            ... )
        """
        if not name:
            raise ValueError("Analyzer name cannot be empty")

        if not module_path or not class_name:
            raise ValueError("Module path and class name are required")

        # Check for duplicate registration with different path
        if name in self._registry:
            existing = self._registry[name]
            if existing.module_path != module_path or existing.class_name != class_name:
                logger.warning(
                    f"Analyzer '{name}' already registered with different path. "
                    f"Overwriting: {existing.module_path}.{existing.class_name} "
                    f"-> {module_path}.{class_name}"
                )

        self._registry[name] = LazyAnalyzerSpec(
            module_path=module_path,
            class_name=class_name,
            category=category,
            formats=formats or set(),
            metadata=metadata or {},
        )

        logger.debug(f"Registered lazy analyzer: {name} -> {module_path}.{class_name}")

    def get_analyzer_class(self, name: str) -> type[Any] | None:
        """
        Get analyzer class, loading module if necessary.

        This is the core lazy loading method. On first access, it imports the
        module and caches the class. Subsequent accesses retrieve from cache
        with O(1) complexity.

        Args:
            name: Analyzer identifier

        Returns:
            Analyzer class reference, or None if not found

        Raises:
            ImportError: If module import fails
            AttributeError: If class not found in module

        Performance:
            - First call: O(1) lookup + import time (~5-10ms)
            - Subsequent calls: O(1) from cache (<1ms)

        Example:
            >>> analyzer_class = loader.get_analyzer_class("pe")
            >>> if analyzer_class:
            ...     analyzer = analyzer_class(r2=r2)
            ...     result = analyzer.analyze()
        """
        if name not in self._registry:
            logger.debug(f"Analyzer '{name}' not found in lazy loader registry")
            return None

        # Check cache first (fast path)
        if name in self._cache:
            self._stats["cache_hits"] += 1
            return self._cache[name]

        self._stats["cache_misses"] += 1

        # Load module (slow path - only happens once per analyzer)
        spec = self._registry[name]
        module_path = spec.module_path
        class_name = spec.class_name

        try:
            import time

            start = time.perf_counter()

            # Thread-safe module import
            module = importlib.import_module(module_path)
            analyzer_class = getattr(module, class_name)

            elapsed = time.perf_counter() - start
            self._stats["load_times"][name] = elapsed * 1000  # Convert to ms

            # Cache the result
            with self._cache_lock:
                self._cache[name] = analyzer_class

            self._stats["load_count"] += 1

            logger.debug(
                f"Loaded analyzer '{name}' from {module_path}.{class_name} "
                f"in {elapsed * 1000:.2f}ms"
            )

            return cast(type[Any], analyzer_class)

        except ImportError as e:
            self._stats["failed_loads"] += 1
            logger.error(f"Failed to import module '{module_path}' for analyzer '{name}': {e}")
            raise

        except AttributeError as e:
            self._stats["failed_loads"] += 1
            logger.error(
                f"Class '{class_name}' not found in module '{module_path}' "
                f"for analyzer '{name}': {e}"
            )
            raise

    def is_loaded(self, name: str) -> bool:
        """
        Check if analyzer module is already loaded.

        This method checks if the analyzer has been imported and cached.
        It does NOT trigger a load if not already loaded.

        Args:
            name: Analyzer identifier

        Returns:
            True if analyzer is loaded and cached, False otherwise

        Example:
            >>> loader.is_loaded("pe")
            False  # Not yet loaded
            >>> loader.get_analyzer_class("pe")  # Load it
            >>> loader.is_loaded("pe")
            True  # Now loaded
        """
        return name in self._cache

    def is_registered(self, name: str) -> bool:
        """
        Check if analyzer is registered for lazy loading.

        Args:
            name: Analyzer identifier

        Returns:
            True if analyzer is registered, False otherwise
        """
        return name in self._registry

    def unload(self, name: str) -> bool:
        """
        Unload an analyzer from cache.

        Removes the analyzer class from cache, forcing a reload on next access.
        The registration metadata is preserved. Useful for testing or
        reloading modified analyzers.

        Args:
            name: Analyzer identifier

        Returns:
            True if analyzer was unloaded, False if not in cache

        Example:
            >>> loader.unload("pe")  # Force reload on next access
        """
        if name in self._cache:
            with self._cache_lock:
                del self._cache[name]
            logger.debug(f"Unloaded analyzer '{name}' from cache")
            return True
        return False

    def unregister(self, name: str) -> bool:
        """
        Unregister an analyzer completely.

        Removes both the registration metadata and cached class.

        Args:
            name: Analyzer identifier

        Returns:
            True if analyzer was unregistered, False if not found

        Example:
            >>> loader.unregister("deprecated_analyzer")
        """
        removed = False

        if name in self._registry:
            del self._registry[name]
            removed = True

        if name in self._cache:
            with self._cache_lock:
                del self._cache[name]
            removed = True

        if removed:
            logger.debug(f"Unregistered analyzer '{name}'")

        return removed

    def preload(self, *names: str) -> dict[str, bool]:
        """
        Preload specific analyzers eagerly.

        Useful for critical analyzers that should be loaded at startup
        rather than lazily. This trades startup time for predictable
        first-access performance.

        Args:
            *names: Analyzer identifiers to preload

        Returns:
            Dictionary mapping analyzer names to success status

        Example:
            >>> # Preload critical analyzers
            >>> loader.preload("pe_analyzer", "elf_analyzer", "file_info")
            {'pe_analyzer': True, 'elf_analyzer': True, 'file_info': True}
        """
        results = {}

        for name in names:
            try:
                self.get_analyzer_class(name)
                results[name] = True
            except (ImportError, AttributeError) as e:
                logger.error(f"Failed to preload analyzer '{name}': {e}")
                results[name] = False

        return results

    def preload_category(self, category: str) -> dict[str, bool]:
        """
        Preload all analyzers in a specific category.

        Args:
            category: Category name to preload

        Returns:
            Dictionary mapping analyzer names to success status

        Example:
            >>> # Preload all format analyzers
            >>> loader.preload_category("format")
        """
        names = [name for name, spec in self._registry.items() if spec.category == category]

        return self.preload(*names)

    def get_stats(self) -> dict[str, Any]:
        """
        Get loading statistics for performance analysis.

        Returns detailed statistics about lazy loading performance,
        including cache hit rate, load counts, and per-analyzer metrics.

        Returns:
            Dictionary containing:
                - registered: Number of registered analyzers
                - loaded: Number of loaded analyzers
                - unloaded: Number of registered but not loaded
                - load_count: Total loads performed
                - cache_hits: Cache hit count
                - cache_misses: Cache miss count
                - failed_loads: Failed import count
                - cache_hit_rate: Cache efficiency (0.0-1.0)
                - lazy_ratio: Fraction of analyzers not yet loaded (0.0-1.0)
                - load_times: Per-analyzer load times in milliseconds

        Example:
            >>> stats = loader.get_stats()
            >>> print(f"Cache hit rate: {stats['cache_hit_rate']:.1%}")
            >>> print(f"Lazy ratio: {stats['lazy_ratio']:.1%}")
        """
        return _build_stats(self)

    def clear_cache(self) -> int:
        """
        Clear all cached analyzers.

        Forces reload on next access for all analyzers. Registration
        metadata is preserved.

        Returns:
            Number of analyzers cleared from cache

        Example:
            >>> count = loader.clear_cache()
            >>> print(f"Cleared {count} analyzers from cache")
        """
        with self._cache_lock:
            count = len(self._cache)
            self._cache.clear()

        logger.debug(f"Cleared {count} analyzers from cache")
        return count

    def list_registered(self) -> dict[str, dict[str, Any]]:
        """
        List all registered analyzers with metadata.

        Returns:
            Dictionary mapping analyzer names to metadata

        Example:
            >>> for name, info in loader.list_registered().items():
            ...     print(f"{name}: {info['module_path']}.{info['class_name']}")
        """
        result = {}

        for name, spec in self._registry.items():
            result[name] = {
                "module_path": spec.module_path,
                "class_name": spec.class_name,
                "category": spec.category,
                "formats": list(spec.formats),
                "loaded": self.is_loaded(name),
                "metadata": spec.metadata,
            }

        return result

    def __len__(self) -> int:
        """Return number of registered analyzers."""
        return len(self._registry)

    def __contains__(self, name: str) -> bool:
        """Check if analyzer is registered."""
        return name in self._registry

    def __repr__(self) -> str:
        """String representation showing loader state."""
        return f"LazyAnalyzerLoader(registered={len(self._registry)}, loaded={len(self._cache)})"


# Global lazy loader instance for convenience
_global_lazy_loader: LazyAnalyzerLoader | None = None


def get_global_lazy_loader() -> LazyAnalyzerLoader:
    """
    Get or create the global lazy loader instance.

    Returns:
        Global LazyAnalyzerLoader instance

    Example:
        >>> from r2inspect.lazy_loader import get_global_lazy_loader
        >>> loader = get_global_lazy_loader()
    """
    global _global_lazy_loader

    if _global_lazy_loader is None:
        _global_lazy_loader = LazyAnalyzerLoader()

    return _global_lazy_loader
