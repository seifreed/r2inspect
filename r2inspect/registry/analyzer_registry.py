#!/usr/bin/env python3
"""Analyzer registry for managing analyzer discovery and metadata."""

import inspect
import logging
import os
from typing import Any, cast

from .categories import AnalyzerCategory
from .entry_points import EntryPointLoader
from .metadata import AnalyzerMetadata
from .metadata_extraction import auto_extract_metadata, extract_metadata_from_class, parse_category
from .registry_queries import AnalyzerRegistryQueries

AnalyzerCategory = AnalyzerCategory
AnalyzerMetadata = AnalyzerMetadata


class AnalyzerRegistry(AnalyzerRegistryQueries):
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

    def _get_base_analyzer_class(self) -> type | None:
        """
        Lazy-load BaseAnalyzer class to avoid circular imports.

        Returns:
            BaseAnalyzer class or None if not available
        """
        if self._base_analyzer_class is None:
            try:
                from ..abstractions.base_analyzer import BaseAnalyzer

                self._base_analyzer_class = BaseAnalyzer
            except ImportError:
                # BaseAnalyzer not available, fall back to non-BaseAnalyzer mode
                pass
        return self._base_analyzer_class

    def is_base_analyzer(self, analyzer_class: type) -> bool:
        """
        Check if a class inherits from BaseAnalyzer.

        Args:
            analyzer_class: Class to check

        Returns:
            True if class inherits from BaseAnalyzer, False otherwise

        Example:
            >>> from r2inspect.modules import PEAnalyzer
            >>> registry.is_base_analyzer(PEAnalyzer)
            True
        """
        base_analyzer = self._get_base_analyzer_class()
        if base_analyzer is None:
            return False

        try:
            return issubclass(analyzer_class, base_analyzer)
        except TypeError:
            # analyzer_class is not a class
            return False

    def extract_metadata_from_class(
        self, analyzer_class: type, name: str | None = None
    ) -> dict[str, Any]:
        """
        Extract metadata from a BaseAnalyzer class.

        Creates a temporary instance (with None parameters) to call metadata
        methods and extract analyzer information. This enables auto-registration
        without manual metadata specification.

        Args:
            analyzer_class: BaseAnalyzer subclass to extract metadata from
            name: Optional name override (uses get_name() if not provided)

        Returns:
            Dictionary containing extracted metadata:
            {
                "name": str,
                "category": str,
                "formats": set[str],
                "description": str
            }

        Raises:
            ValueError: If analyzer_class doesn't inherit from BaseAnalyzer
            RuntimeError: If metadata extraction fails

        Example:
            >>> metadata = registry.extract_metadata_from_class(PEAnalyzer)
            >>> print(metadata["name"])
            'pe'
            >>> print(metadata["category"])
            'format'
        """
        return extract_metadata_from_class(
            analyzer_class, is_base_analyzer=self.is_base_analyzer, name=name
        )

    def _parse_category(self, category_value: Any) -> AnalyzerCategory:
        """
        Parse category value into AnalyzerCategory enum.

        Handles both string and AnalyzerCategory enum values.

        Args:
            category_value: Either AnalyzerCategory enum or string

        Returns:
            AnalyzerCategory enum instance

        Raises:
            ValueError: If category string is invalid
            TypeError: If category type is invalid
        """
        return parse_category(category_value)

    def validate_analyzer(self, analyzer_class: type) -> tuple[bool, str | None]:
        """
        Validate that an analyzer class meets requirements.

        Checks if the analyzer class is properly formed and implements
        required methods. For BaseAnalyzer subclasses, validates that
        abstract methods are implemented.

        Args:
            analyzer_class: Analyzer class to validate

        Returns:
            Tuple of (is_valid, error_message)
            - (True, None) if valid
            - (False, "error description") if invalid

        Example:
            >>> is_valid, error = registry.validate_analyzer(PEAnalyzer)
            >>> if not is_valid:
            ...     print(f"Invalid analyzer: {error}")
        """
        # Check if it's a class
        if not inspect.isclass(analyzer_class):
            return False, "analyzer_class must be a class, not an instance"

        # If it's a BaseAnalyzer, check abstract methods
        if self.is_base_analyzer(analyzer_class):
            # Check if analyze() is implemented
            if not hasattr(analyzer_class, "analyze"):
                return False, "BaseAnalyzer subclass must implement analyze() method"

            # Check if analyze is still abstract
            if hasattr(analyzer_class.analyze, "__isabstractmethod__"):
                if analyzer_class.analyze.__isabstractmethod__:
                    return False, "analyze() method is not implemented (still abstract)"

        # Check if class is instantiable (has __init__)
        if not hasattr(analyzer_class, "__init__"):
            return False, "Analyzer class must have __init__ method"

        return True, None

    def register_from_instance(
        self,
        analyzer_instance: Any,
        name: str | None = None,
        required: bool = False,
        dependencies: set[str] | None = None,
        override_category: AnalyzerCategory | None = None,
        override_formats: set[str] | None = None,
        override_description: str | None = None,
    ) -> None:
        """
        Register an analyzer from a BaseAnalyzer instance.

        Auto-extracts metadata from the instance using BaseAnalyzer methods,
        eliminating the need to manually specify name, category, formats, and
        description. Useful for simplified registration syntax.

        Args:
            analyzer_instance: BaseAnalyzer instance to register
            name: Optional name override (uses instance.get_name() if not provided)
            required: Whether analyzer must always execute
            dependencies: Set of analyzer names this depends on
            override_category: Optional category override
            override_formats: Optional formats override
            override_description: Optional description override

        Raises:
            ValueError: If instance is not a BaseAnalyzer subclass
            RuntimeError: If metadata extraction fails

        Example:
            >>> # Simple registration with auto-metadata
            >>> pe_analyzer = PEAnalyzer(r2=None, config=None)
            >>> registry.register_from_instance(pe_analyzer, required=True)
            >>>
            >>> # With overrides
            >>> registry.register_from_instance(
            ...     pe_analyzer,
            ...     name="custom_pe",
            ...     override_description="Custom PE analyzer"
            ... )
        """
        # Validate it's a BaseAnalyzer instance
        if not self.is_base_analyzer(type(analyzer_instance)):
            raise ValueError(f"{type(analyzer_instance).__name__} is not a BaseAnalyzer subclass")

        # Extract metadata from instance
        extracted_name = name or analyzer_instance.get_name()
        category_str = override_category or analyzer_instance.get_category()
        formats = (
            override_formats
            if override_formats is not None
            else analyzer_instance.get_supported_formats()
        )
        description = override_description or analyzer_instance.get_description()

        # Parse category
        category_enum = self._parse_category(category_str)

        # Create metadata
        metadata = AnalyzerMetadata(
            name=extracted_name,
            analyzer_class=type(analyzer_instance),
            category=category_enum,
            file_formats=formats,
            required=required,
            dependencies=dependencies or set(),
            description=description,
        )

        self._analyzers[extracted_name] = metadata

    def register(
        self,
        name: str,
        analyzer_class: type | None = None,
        category: AnalyzerCategory | str | None = None,
        file_formats: set[str] | None = None,
        required: bool = False,
        dependencies: set[str] | None = None,
        description: str = "",
        auto_extract: bool = True,
        module_path: str | None = None,
        class_name: str | None = None,
    ) -> None:
        """
        Register an analyzer with the registry.

        Enhanced registration that supports:
        1. Manual metadata specification
        2. Automatic metadata extraction from BaseAnalyzer subclasses
        3. Lazy loading for performance optimization

        Registration Modes:

        A) Eager Registration (traditional):
           Provide analyzer_class - class imported and stored immediately

        B) Lazy Registration (optimized):
           Provide module_path and class_name - import deferred until first access
           Reduces startup time by 80-90%

        C) Auto-extraction Mode:
           Provide analyzer_class with auto_extract=True - metadata extracted
           from BaseAnalyzer methods

        Args:
            name: Unique identifier for the analyzer
            analyzer_class: Class reference (eager mode) - mutually exclusive with lazy
            category: Semantic category from AnalyzerCategory enum
                     (auto-extracted from BaseAnalyzer if None and auto_extract=True)
            file_formats: Set of supported formats (None = all formats)
                         (auto-extracted from BaseAnalyzer if None and auto_extract=True)
            required: Whether analyzer must always execute
            dependencies: Set of analyzer names this depends on
            description: Human-readable description
                        (auto-extracted from BaseAnalyzer if empty and auto_extract=True)
            auto_extract: Enable automatic metadata extraction from BaseAnalyzer
            module_path: Module path for lazy loading (e.g., "r2inspect.modules.pe_analyzer")
            class_name: Class name for lazy loading (e.g., "PEAnalyzer")

        Raises:
            ValueError: If name is empty or invalid argument combination
            TypeError: If category is not an AnalyzerCategory instance

        Examples:
            >>> # Traditional eager registration
            >>> registry.register(
            ...     name="ssdeep",
            ...     analyzer_class=SSDeepAnalyzer,
            ...     category=AnalyzerCategory.HASHING,
            ...     file_formats=None,
            ...     required=False,
            ...     description="Fuzzy hashing for file similarity"
            ... )
            >>>
            >>> # Lazy registration (optimized for startup performance)
            >>> registry.register(
            ...     name="pe",
            ...     module_path="r2inspect.modules.pe_analyzer",
            ...     class_name="PEAnalyzer",
            ...     category=AnalyzerCategory.FORMAT,
            ...     file_formats={"PE", "PE32", "PE32+"},
            ...     required=True,
            ...     description="PE format analyzer"
            ... )
            >>>
            >>> # Auto-extraction for BaseAnalyzer subclass
            >>> registry.register(
            ...     name="pe_analyzer",
            ...     analyzer_class=PEAnalyzer,
            ...     required=True
            ...     # category, file_formats, description auto-extracted!
            ... )
        """
        self._validate_registration_name(name)

        is_lazy, _ = self._resolve_registration_mode(analyzer_class, module_path, class_name)

        if is_lazy:
            lazy_result = self._handle_lazy_registration(
                name=name,
                module_path=module_path,
                class_name=class_name,
                category=category,
                file_formats=file_formats,
                required=required,
                dependencies=dependencies,
                description=description,
            )
            if lazy_result is not None:
                return
            analyzer_class = self._lazy_fallback_analyzer_class(module_path, class_name)
            auto_extract = False

        analyzer_class = self._ensure_analyzer_class(analyzer_class)
        category, file_formats, description = self._auto_extract_metadata(
            analyzer_class=analyzer_class,
            name=name,
            category=category,
            file_formats=file_formats,
            description=description,
            auto_extract=auto_extract,
        )
        category = self._ensure_category(analyzer_class, category)

        metadata = AnalyzerMetadata(
            name=name,
            analyzer_class=analyzer_class,
            category=category,
            file_formats=file_formats,
            required=required,
            dependencies=dependencies,
            description=description,
        )

        self._analyzers[name] = metadata

    def _validate_registration_name(self, name: str) -> None:
        """Validate analyzer registration name."""
        if not name:
            raise ValueError("Analyzer name cannot be empty")

    def _resolve_registration_mode(
        self,
        analyzer_class: type | None,
        module_path: str | None,
        class_name: str | None,
    ) -> tuple[bool, bool]:
        """Determine eager/lazy registration mode."""
        is_lazy = module_path is not None and class_name is not None
        is_eager = analyzer_class is not None
        if not is_lazy and not is_eager:
            raise ValueError(
                "Must provide either analyzer_class (eager) or module_path+class_name (lazy)"
            )
        if is_lazy and is_eager:
            raise ValueError(
                "Cannot provide both analyzer_class and module_path+class_name. "
                "Choose eager or lazy registration."
            )
        return is_lazy, is_eager

    def _handle_lazy_registration(
        self,
        name: str,
        module_path: str | None,
        class_name: str | None,
        category: AnalyzerCategory | str | None,
        file_formats: set[str] | None,
        required: bool,
        dependencies: set[str] | None,
        description: str,
    ) -> AnalyzerMetadata | None:
        """Register analyzer lazily or return None to fall back to eager."""
        if module_path is None or class_name is None:
            raise ValueError("module_path and class_name are required for lazy registration")
        if category is None:
            raise ValueError(f"Category is required for lazy registration of analyzer '{name}'")

        resolved_category = (
            category if isinstance(category, AnalyzerCategory) else self._parse_category(category)
        )

        if self._lazy_loading and self._lazy_loader is not None:
            lazy_module_path: str = module_path
            lazy_class_name: str = class_name
            self._lazy_loader.register(
                name=name,
                module_path=lazy_module_path,
                class_name=lazy_class_name,
                category=resolved_category.value,
                formats=file_formats,
                metadata={
                    "required": required,
                    "dependencies": dependencies or set(),
                    "description": description,
                },
            )

            class LazyPlaceholder:
                """Placeholder for lazy-loaded analyzer class"""

                __name__ = lazy_class_name
                __module__ = lazy_module_path

            metadata = AnalyzerMetadata(
                name=name,
                analyzer_class=LazyPlaceholder,
                category=resolved_category,
                file_formats=file_formats,
                required=required,
                dependencies=dependencies,
                description=description,
            )

            self._analyzers[name] = metadata
            return metadata
        return None

    def _lazy_fallback_analyzer_class(
        self, module_path: str | None, class_name: str | None
    ) -> type:
        """Import analyzer class when lazy loading is disabled."""
        if module_path is None or class_name is None:
            raise ValueError("module_path and class_name are required for lazy fallback")
        import importlib

        module = importlib.import_module(module_path)
        return cast(type[Any], getattr(module, class_name))

    def _ensure_analyzer_class(self, analyzer_class: type | None) -> type:
        """Ensure analyzer class is provided."""
        if analyzer_class is None:
            raise ValueError("analyzer_class is required for eager registration")
        return analyzer_class

    def _auto_extract_metadata(
        self,
        analyzer_class: type,
        name: str,
        category: AnalyzerCategory | str | None,
        file_formats: set[str] | None,
        description: str,
        auto_extract: bool,
    ) -> tuple[AnalyzerCategory | str | None, set[str] | None, str]:
        """Auto-extract metadata from BaseAnalyzer subclasses when enabled."""
        return auto_extract_metadata(
            analyzer_class,
            name=name,
            category=category,
            file_formats=file_formats,
            description=description,
            auto_extract=auto_extract,
            is_base_analyzer=self.is_base_analyzer,
        )

    def _ensure_category(
        self, analyzer_class: type, category: AnalyzerCategory | str | None
    ) -> AnalyzerCategory:
        """Ensure category is provided and normalized."""
        if category is None:
            raise ValueError(
                f"Category must be provided for {analyzer_class.__name__}. "
                "Either specify category parameter or ensure analyzer inherits from "
                "BaseAnalyzer with get_category() implemented."
            )
        if not isinstance(category, AnalyzerCategory):
            return self._parse_category(category)
        return category

    def unregister(self, name: str) -> bool:
        """
        Remove an analyzer from the registry.

        Args:
            name: Analyzer identifier to remove

        Returns:
            True if analyzer was removed, False if not found

        Example:
            >>> registry.unregister("deprecated_analyzer")
            True
        """
        if name in self._analyzers:
            del self._analyzers[name]
            return True
        return False

    def is_registered(self, name: str) -> bool:
        """
        Check if an analyzer is registered.

        Args:
            name: Analyzer identifier to check

        Returns:
            True if analyzer is registered
        """
        return name in self._analyzers

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
