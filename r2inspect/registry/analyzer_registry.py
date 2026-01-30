#!/usr/bin/env python3
"""
Analyzer Registry Module

This module implements the Registry Pattern for managing binary analyzers in r2inspect.
It provides centralized registration, discovery, and instantiation of analyzer classes
based on file format, category, and requirements.

The registry pattern decouples the core analysis engine from concrete analyzer
implementations, enabling dynamic configuration, plugin architectures, and
flexible analyzer selection strategies.

Copyright (C) 2025 Marc Rivero López

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

import inspect
import logging
import os
from enum import Enum
from importlib import import_module
from typing import Any

try:
    # Python 3.10+
    from importlib.metadata import EntryPoint
    from importlib.metadata import entry_points as _entry_points

    entry_points: Any = _entry_points
except Exception:  # pragma: no cover
    entry_points = None
    EntryPoint = Any  # type: ignore


class AnalyzerCategory(Enum):
    """
    Categorization of analyzer types.

    This enumeration provides semantic grouping of analyzers based on their
    primary function within the analysis pipeline. Categories enable filtered
    queries and selective execution of analyzer subsets.

    Categories:
        FORMAT: File format-specific analyzers (PE, ELF, Mach-O)
        HASHING: Hash computation and fuzzy matching (SSDeep, TLSH, Impfuzzy)
        DETECTION: Pattern matching and signature detection (Packer, Crypto, Anti-Analysis)
        METADATA: Structural metadata extraction (Sections, Imports, Exports, Compiler)
        SECURITY: Security feature analysis (Mitigations, Authenticode, Signatures)
        SIMILARITY: Code similarity and diffing (BinDiff, SimHash, Binbloom)
        BEHAVIORAL: Behavioral analysis (YARA, String analysis, Function analysis)
    """

    FORMAT = "format"
    HASHING = "hashing"
    DETECTION = "detection"
    METADATA = "metadata"
    SECURITY = "security"
    SIMILARITY = "similarity"
    BEHAVIORAL = "behavioral"


class AnalyzerMetadata:
    """
    Metadata container for registered analyzers.

    Encapsulates all registration information for a single analyzer,
    including its class reference, categorization, format applicability,
    execution requirements, and dependency relationships.

    Attributes:
        name: Unique identifier for the analyzer
        analyzer_class: Class reference to the analyzer implementation
        category: Semantic category from AnalyzerCategory enum
        file_formats: Set of supported file formats (e.g., {"PE", "PE32", "PE32+"})
        required: Whether this analyzer must always execute
        dependencies: Set of analyzer names that must execute before this one
        description: Human-readable description of analyzer functionality
    """

    def __init__(
        self,
        name: str,
        analyzer_class: type,
        category: AnalyzerCategory,
        file_formats: set[str] | None = None,
        required: bool = False,
        dependencies: set[str] | None = None,
        description: str = "",
    ):
        """
        Initialize analyzer metadata.

        Args:
            name: Unique analyzer identifier
            analyzer_class: Reference to analyzer class
            category: Analyzer category from AnalyzerCategory enum
            file_formats: Set of supported file formats (None = all formats)
            required: Whether analyzer is required for all analyses
            dependencies: Set of analyzer names this analyzer depends on
            description: Human-readable description

        Raises:
            ValueError: If name is empty or analyzer_class is None
            TypeError: If category is not an AnalyzerCategory instance
        """
        if not name:
            raise ValueError("Analyzer name cannot be empty")
        if analyzer_class is None:
            raise ValueError("Analyzer class cannot be None")
        if not isinstance(category, AnalyzerCategory):
            raise TypeError(f"Category must be AnalyzerCategory, got {type(category)}")

        self.name = name
        self.analyzer_class = analyzer_class
        self.category = category
        self.file_formats = file_formats or set()
        self.required = required
        self.dependencies = dependencies or set()
        self.description = description

    def supports_format(self, file_format: str) -> bool:
        """
        Check if analyzer supports a specific file format.

        Args:
            file_format: File format identifier (e.g., "PE", "ELF")

        Returns:
            True if analyzer supports the format or supports all formats
        """
        # Empty file_formats means analyzer supports all formats
        if not self.file_formats:
            return True
        return file_format.upper() in {fmt.upper() for fmt in self.file_formats}

    def to_dict(self) -> dict[str, Any]:
        """
        Convert metadata to dictionary representation.

        Returns:
            Dictionary containing all metadata fields
        """
        return {
            "name": self.name,
            "class": self.analyzer_class.__name__,
            "module": self.analyzer_class.__module__,
            "category": self.category.value,
            "file_formats": list(self.file_formats),
            "required": self.required,
            "dependencies": list(self.dependencies),
            "description": self.description,
        }


class AnalyzerRegistry:
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
        if not self.is_base_analyzer(analyzer_class):
            raise ValueError(f"{analyzer_class.__name__} does not inherit from BaseAnalyzer")

        try:
            # Create temporary instance with None parameters
            # BaseAnalyzer accepts r2=None, config=None, filepath=None
            temp_instance = analyzer_class(r2=None, config=None, filepath=None)

            # Extract metadata using BaseAnalyzer methods
            extracted_name = name or temp_instance.get_name()
            category_str = temp_instance.get_category()
            formats = temp_instance.get_supported_formats()
            description = temp_instance.get_description()

            return {
                "name": extracted_name,
                "category": category_str,
                "formats": formats,
                "description": description,
            }

        except Exception as e:
            raise RuntimeError(f"Failed to extract metadata from {analyzer_class.__name__}: {e}")

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
        if isinstance(category_value, AnalyzerCategory):
            return category_value

        if isinstance(category_value, str):
            # Try to match string to enum value
            category_str = category_value.lower()
            for cat in AnalyzerCategory:
                if cat.value == category_str:
                    return cat
            raise ValueError(
                f"Unknown category string: {category_value}. "
                f"Valid categories: {[c.value for c in AnalyzerCategory]}"
            )

        raise TypeError(
            f"Category must be AnalyzerCategory enum or string, got {type(category_value)}"
        )

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
        1. Manual metadata specification (backward compatible)
        2. Automatic metadata extraction from BaseAnalyzer subclasses
        3. Lazy loading for performance optimization (new)

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
        return getattr(module, class_name)

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
        if not auto_extract or not self.is_base_analyzer(analyzer_class):
            return category, file_formats, description
        try:
            extracted = self.extract_metadata_from_class(analyzer_class, name=name)
            if category is None:
                category = self._parse_category(extracted["category"])
            if file_formats is None:
                file_formats = extracted["formats"]
            if not description:
                description = extracted["description"]
        except Exception as e:
            import logging

            logging.getLogger(__name__).warning(
                f"Auto-extraction failed for {analyzer_class.__name__}: {e}. "
                f"Using provided metadata."
            )
        return category, file_formats, description

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

        Performance:
            - Eager analyzers: O(1) dictionary lookup
            - Lazy analyzers (first call): O(1) + import time (~5-10ms)
            - Lazy analyzers (cached): O(1) dictionary lookup

        Example:
            >>> PEAnalyzerClass = registry.get_analyzer_class("pe_analyzer")
            >>> if PEAnalyzerClass:
            ...     analyzer = PEAnalyzerClass(r2, config)
        """
        metadata = self._analyzers.get(name)
        if not metadata:
            return None

        # Check if this is a lazy-loaded analyzer
        if self._lazy_loading and self._lazy_loader and self._lazy_loader.is_registered(name):
            # Get from lazy loader (triggers import if not cached)
            return self._lazy_loader.get_analyzer_class(name)

        # Return eagerly loaded class
        return metadata.analyzer_class

    def get_analyzers_for_format(self, file_format: str) -> dict[str, type]:
        """
        Retrieve all analyzers that support a specific file format.

        Returns a dictionary mapping analyzer names to their class references
        for all analyzers that declare support for the specified format.
        Analyzers with empty file_formats sets (universal analyzers) are
        included for all format queries.

        Args:
            file_format: File format identifier (e.g., "PE", "ELF", "MACH0")

        Returns:
            Dictionary mapping analyzer names to class references

        Example:
            >>> pe_analyzers = registry.get_analyzers_for_format("PE")
            >>> for name, analyzer_class in pe_analyzers.items():
            ...     print(f"{name}: {analyzer_class.__name__}")
            pe_analyzer: PEAnalyzer
            authenticode: AuthenticodeAnalyzer
            rich_header: RichHeaderAnalyzer
        """
        result = {}
        for name, metadata in self._analyzers.items():
            if metadata.supports_format(file_format):
                result[name] = metadata.analyzer_class
        return result

    # ---------------------------------------------------------------------
    # Plugin loading via entry points
    # ---------------------------------------------------------------------
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
        loaded = 0
        if entry_points is None:
            return loaded

        eps_group = self._get_entry_points_group(group)
        if not eps_group:
            return loaded

        for ep in eps_group:
            loaded += self._handle_entry_point(ep)
        return loaded

    def _get_entry_points_group(self, group: str) -> list[Any]:
        """Fetch entry points for a group with compatibility handling."""
        try:
            eps = entry_points()
            return (
                list(eps.select(group=group))
                if hasattr(eps, "select")
                else list(eps.get(group, []))
            )
        except Exception:
            logging.getLogger(__name__).debug("No entry points available")
            return []

    def _handle_entry_point(self, ep: Any) -> int:
        """Load and register a single entry point."""
        try:
            obj = ep.load()
        except Exception as e:
            logging.getLogger(__name__).warning(
                f"Failed to load entry point '{getattr(ep, 'name', '?')}': {e}"
            )
            return 0

        if callable(obj):
            return self._register_entry_point_callable(ep, obj)

        if inspect.isclass(obj):
            return self._register_entry_point_class(ep, obj)

        return 0

    def _register_entry_point_callable(self, ep: Any, obj: Any) -> int:
        """Invoke a callable entry point that self-registers."""
        try:
            obj(self)
            return 1
        except Exception as e:
            logging.getLogger(__name__).warning(f"Entry point '{ep.name}' callable failed: {e}")
            return 0

    def _register_entry_point_class(self, ep: Any, obj: Any) -> int:
        """Register an analyzer class from an entry point."""
        try:
            name = self._derive_entry_point_name(ep, obj)
            self.register(
                name=name,
                analyzer_class=obj,
                required=False,
                auto_extract=True,
                category=self._parse_category("metadata"),
            )
            return 1
        except Exception as e:
            logging.getLogger(__name__).warning(f"Failed to register entry point '{ep.name}': {e}")
            return 0

    def _derive_entry_point_name(self, ep: Any, obj: Any) -> str:
        """Determine analyzer name from entry point class."""
        if self.is_base_analyzer(obj):
            meta = self.extract_metadata_from_class(obj)
            return meta["name"]
        return ep.name

    def get_by_category(self, category: AnalyzerCategory) -> dict[str, type]:
        """
        Retrieve all analyzers in a specific category.

        Args:
            category: Category to filter by

        Returns:
            Dictionary mapping analyzer names to class references

        Raises:
            TypeError: If category is not an AnalyzerCategory instance

        Example:
            >>> hashers = registry.get_by_category(AnalyzerCategory.HASHING)
            >>> for name, analyzer_class in hashers.items():
            ...     print(f"{name}: {analyzer_class.__name__}")
            ssdeep: SSDeepAnalyzer
            tlsh: TLSHAnalyzer
            impfuzzy: ImpfuzzyAnalyzer
        """
        if not isinstance(category, AnalyzerCategory):
            raise TypeError(f"Category must be AnalyzerCategory, got {type(category)}")

        result = {}
        for name, metadata in self._analyzers.items():
            if metadata.category == category:
                result[name] = metadata.analyzer_class
        return result

    def get_required_analyzers(self) -> dict[str, type]:
        """
        Retrieve all analyzers marked as required.

        Required analyzers are those that must always execute regardless of
        file format or user configuration. These typically include core
        functionality essential for basic analysis.

        Returns:
            Dictionary mapping analyzer names to class references

        Example:
            >>> required = registry.get_required_analyzers()
            >>> # These will always run
        """
        result = {}
        for name, metadata in self._analyzers.items():
            if metadata.required:
                result[name] = metadata.analyzer_class
        return result

    def get_optional_analyzers(self) -> dict[str, type]:
        """
        Retrieve all analyzers marked as optional.

        Optional analyzers can be selectively enabled/disabled based on
        user configuration, file format, or runtime conditions.

        Returns:
            Dictionary mapping analyzer names to class references

        Example:
            >>> optional = registry.get_optional_analyzers()
            >>> # User can choose which of these to run
        """
        result = {}
        for name, metadata in self._analyzers.items():
            if not metadata.required:
                result[name] = metadata.analyzer_class
        return result

    def list_analyzers(self) -> list[dict[str, Any]]:
        """
        List all registered analyzers with their metadata.

        Returns a list of dictionaries containing complete metadata for
        each registered analyzer. Useful for introspection, debugging,
        and generating documentation.

        Returns:
            List of dictionaries with analyzer metadata

        Example:
            >>> for analyzer_info in registry.list_analyzers():
            ...     print(f"{analyzer_info['name']}: {analyzer_info['category']}")
            ...     print(f"  Formats: {', '.join(analyzer_info['file_formats'])}")
            ...     print(f"  Required: {analyzer_info['required']}")
        """
        return [metadata.to_dict() for metadata in self._analyzers.values()]

    def get_dependencies(self, name: str) -> set[str]:
        """
        Retrieve dependencies for a specific analyzer.

        Args:
            name: Analyzer identifier

        Returns:
            Set of analyzer names this analyzer depends on (empty if none)

        Example:
            >>> deps = registry.get_dependencies("rich_header")
            >>> # Returns analyzers that must run before rich_header
        """
        metadata = self._analyzers.get(name)
        return metadata.dependencies.copy() if metadata else set()

    def resolve_execution_order(self, analyzer_names: list[str]) -> list[str]:
        """
        Resolve execution order based on dependencies.

        Performs topological sort to determine the correct execution order
        for a set of analyzers based on their declared dependencies.

        Args:
            analyzer_names: List of analyzer names to order

        Returns:
            Ordered list of analyzer names respecting dependencies

        Raises:
            ValueError: If circular dependencies are detected
            KeyError: If an unknown analyzer or dependency is referenced

        Example:
            >>> order = registry.resolve_execution_order(
            ...     ["rich_header", "pe_analyzer", "impfuzzy"]
            ... )
            >>> # Returns ordered list: pe_analyzer must run before rich_header
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
        """
        Remove all registered analyzers.

        Clears the entire registry. Useful for testing or reinitialization.
        """
        self._analyzers.clear()

    def __len__(self) -> int:
        """Return the number of registered analyzers."""
        return len(self._analyzers)

    def __contains__(self, name: str) -> bool:
        """Check if an analyzer is registered using 'in' operator."""
        return name in self._analyzers

    def __iter__(self):
        """Iterate over analyzer names."""
        return iter(self._analyzers)
