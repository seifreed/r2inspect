#!/usr/bin/env python3
"""Analyzer registry for managing analyzer discovery and metadata."""

import os

from .categories import AnalyzerCategory
from .entry_points import EntryPointLoader
from .metadata import AnalyzerMetadata
from .registry_base import AnalyzerRegistryBaseMixin
from .registry_registration import AnalyzerRegistryRegistrationMixin
from .registry_queries import AnalyzerRegistryQueries

AnalyzerCategory = AnalyzerCategory
AnalyzerMetadata = AnalyzerMetadata


class AnalyzerRegistry(
    AnalyzerRegistryRegistrationMixin, AnalyzerRegistryBaseMixin, AnalyzerRegistryQueries
):
    """
    Central registry for binary analyzer management.

    This class implements the Registry Pattern, providing centralized registration,
    discovery, and retrieval of analyzer classes. It supports filtering by format,
    category, and requirement level, enabling flexible analyzer selection strategies.

    The registry maintains metadata about each analyzer including its supported
    file formats, categorization, dependency relationships, and execution requirements.
    This enables sophisticated analyzer orchestration and dynamic configuration.

    Design Principles:
        - Single Responsibility: Manages only analyzer registration and discovery
        - Open/Closed: Open for extension via registration, closed for modification
        - Dependency Inversion: Depends on abstractions (type), not concrete classes
        - Interface Segregation: Provides focused query methods for specific use cases

    Thread Safety:
        This implementation is not thread-safe. For concurrent access, external
        synchronization is required.

    Example:
        >>> registry = AnalyzerRegistry()
        >>> registry.register(
        ...     name="pe_analyzer",
        ...     analyzer_class=PEAnalyzer,
        ...     category=AnalyzerCategory.FORMAT,
        ...     file_formats={"PE", "PE32", "PE32+"},
        ...     required=True
        ... )
        >>>
        >>> # Get all analyzers for PE files
        >>> pe_analyzers = registry.get_analyzers_for_format("PE")
        >>>
        >>> # Get only hashing analyzers
        >>> hashers = registry.get_by_category(AnalyzerCategory.HASHING)
    """

    def __init__(self, lazy_loading: bool | None = None):
        """
        Initialize analyzer registry with optional lazy loading.

        Args:
            lazy_loading: Enable lazy loading of analyzers. If None, checks
                         R2INSPECT_LAZY_LOADING environment variable (default: True)
        """
        self._analyzers: dict[str, AnalyzerMetadata] = {}

        # Determine lazy loading setting
        if lazy_loading is None:
            # Check environment variable, default to True
            env_value = os.getenv("R2INSPECT_LAZY_LOADING", "1")
            lazy_loading = env_value.lower() not in ("0", "false", "no", "off")

        self._lazy_loading = lazy_loading

        # Initialize lazy loader if enabled
        if self._lazy_loading:
            from ..lazy_loader import LazyAnalyzerLoader

            self._lazy_loader: LazyAnalyzerLoader | None = LazyAnalyzerLoader()
        else:
            self._lazy_loader = None
        self._base_analyzer_class: type | None = None  # Lazy-loaded to avoid circular imports

    def load_entry_points(self, group: str = "r2inspect.analyzers") -> int:
        """
        Load external analyzers registered via Python entry points.

        Supports two styles of entry points:
            - A callable taking (registry) and registering analyzers
            - A BaseAnalyzer subclass (auto-metadata extraction)

        Args:
            group: Entry point group name

        Returns:
            Number of analyzers (or providers) loaded
        """
        return EntryPointLoader(self).load(group)
