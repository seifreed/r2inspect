#!/usr/bin/env python3
"""Query and dependency helpers for AnalyzerRegistry."""

from __future__ import annotations

from typing import Any, cast

from .categories import AnalyzerCategory
from .metadata import AnalyzerMetadata


class AnalyzerRegistryQueries:
    """Query and dependency resolution mixin for analyzer registries."""

    _analyzers: dict[str, AnalyzerMetadata]
    _lazy_loading: bool
    _lazy_loader: Any | None

    def get_metadata(self, name: str) -> AnalyzerMetadata | None:
        """
        Retrieve metadata for a specific analyzer.

        Args:
            name: Analyzer identifier

        Returns:
            AnalyzerMetadata instance or None if not found
        """
        return self._analyzers.get(name)

    def get_analyzer_class(self, name: str) -> type | None:
        """
        Retrieve the class reference for a specific analyzer.

        Supports both eager and lazy-loaded analyzers. For lazy-loaded
        analyzers, the module is imported on first access and cached
        for subsequent calls.

        Args:
            name: Analyzer identifier

        Returns:
            Analyzer class reference or None if not found
        """
        metadata = self._analyzers.get(name)
        if not metadata:
            return None

        # Check if this is a lazy-loaded analyzer
        if self._lazy_loading and self._lazy_loader and self._lazy_loader.is_registered(name):
            # Get from lazy loader (triggers import if not cached)
            return cast(type | None, self._lazy_loader.get_analyzer_class(name))

        # Return eagerly loaded class
        return metadata.analyzer_class

    def get_analyzers_for_format(self, file_format: str) -> dict[str, type]:
        """
        Retrieve all analyzers that support a specific file format.

        Args:
            file_format: File format identifier (e.g., "PE", "ELF", "MACH0")

        Returns:
            Dictionary mapping analyzer names to class references
        """
        result = {}
        for name, metadata in self._analyzers.items():
            if not metadata.supports_format(file_format):
                continue
            analyzer_class = self.get_analyzer_class(name)
            if analyzer_class:
                result[name] = analyzer_class
        return result

    def get_by_category(self, category: AnalyzerCategory) -> dict[str, type]:
        """
        Retrieve all analyzers in a specific category.

        Args:
            category: Category to filter by

        Returns:
            Dictionary mapping analyzer names to class references
        """
        if not isinstance(category, AnalyzerCategory):
            raise TypeError(f"Category must be AnalyzerCategory, got {type(category)}")

        result = {}
        for name, metadata in self._analyzers.items():
            if metadata.category != category:
                continue
            analyzer_class = self.get_analyzer_class(name)
            if analyzer_class:
                result[name] = analyzer_class
        return result

    def get_required_analyzers(self) -> dict[str, type]:
        """Retrieve all analyzers marked as required."""
        result = {}
        for name, metadata in self._analyzers.items():
            if not metadata.required:
                continue
            analyzer_class = self.get_analyzer_class(name)
            if analyzer_class:
                result[name] = analyzer_class
        return result

    def get_optional_analyzers(self) -> dict[str, type]:
        """Retrieve all analyzers marked as optional."""
        result = {}
        for name, metadata in self._analyzers.items():
            if metadata.required:
                continue
            analyzer_class = self.get_analyzer_class(name)
            if analyzer_class:
                result[name] = analyzer_class
        return result

    def list_analyzers(self) -> list[dict[str, Any]]:
        """List all registered analyzers with their metadata."""
        return [metadata.to_dict() for metadata in self._analyzers.values()]

    def get_dependencies(self, name: str) -> set[str]:
        """Retrieve dependencies for a specific analyzer."""
        metadata = self._analyzers.get(name)
        return metadata.dependencies.copy() if metadata and metadata.dependencies else set()

    def resolve_execution_order(self, analyzer_names: list[str]) -> list[str]:
        """
        Resolve execution order based on dependencies.

        Args:
            analyzer_names: List of analyzer names to order

        Returns:
            Ordered list of analyzer names respecting dependencies
        """
        graph, in_degree = self._build_dependency_graph(analyzer_names)
        self._calculate_in_degrees(graph, in_degree, analyzer_names)
        result = self._topological_sort(graph, in_degree, analyzer_names)
        if len(result) != len(analyzer_names):
            raise ValueError("Circular dependency detected in analyzer dependencies")
        return result

    def _build_dependency_graph(
        self, analyzer_names: list[str]
    ) -> tuple[dict[str, set[str]], dict[str, int]]:
        """Build dependency graph and initialize in-degree counts."""
        graph: dict[str, set[str]] = {}
        in_degree: dict[str, int] = {}
        for name in analyzer_names:
            if name not in self._analyzers:
                raise KeyError(f"Unknown analyzer: {name}")
            graph[name] = self.get_dependencies(name)
            in_degree[name] = 0
        return graph, in_degree

    def _calculate_in_degrees(
        self,
        graph: dict[str, set[str]],
        in_degree: dict[str, int],
        analyzer_names: list[str],
    ) -> None:
        """Calculate in-degree counts for topological sort."""
        for name in analyzer_names:
            for dep in graph[name]:
                if dep not in analyzer_names:
                    continue
                in_degree[dep] = in_degree.get(dep, 0)
                in_degree[name] = in_degree.get(name, 0) + 1

    def _topological_sort(
        self,
        graph: dict[str, set[str]],
        in_degree: dict[str, int],
        analyzer_names: list[str],
    ) -> list[str]:
        """Perform Kahn's algorithm to order analyzers."""
        queue = [name for name in analyzer_names if in_degree[name] == 0]
        result: list[str] = []
        while queue:
            current = queue.pop(0)
            result.append(current)
            for name in analyzer_names:
                if current in graph[name]:
                    in_degree[name] -= 1
                    if in_degree[name] == 0:
                        queue.append(name)
        return result

    def clear(self) -> None:
        """Remove all registered analyzers."""
        self._analyzers.clear()

    def __len__(self) -> int:
        """Return the number of registered analyzers."""
        return len(self._analyzers)

    def __contains__(self, name: str) -> bool:
        """Check if an analyzer is registered using 'in' operator."""
        return name in self._analyzers

    def __iter__(self) -> Any:
        """Iterate over analyzer names."""
        return iter(self._analyzers)
