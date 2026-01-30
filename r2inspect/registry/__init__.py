#!/usr/bin/env python3
"""
r2inspect Registry Module

This module provides the Registry Pattern implementation for managing binary
analyzers in r2inspect. It enables centralized registration, discovery, and
orchestration of analyzer classes.

The registry pattern decouples the core analysis engine from concrete analyzer
implementations, enabling:
    - Dynamic analyzer discovery and instantiation
    - Plugin architecture support
    - Format-specific analyzer selection
    - Category-based filtering
    - Dependency management
    - External configuration of analyzer sets

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

Examples:
    Basic registry usage:

    >>> from r2inspect.registry import create_default_registry, AnalyzerCategory
    >>>
    >>> # Create default registry with all analyzers
    >>> registry = create_default_registry()
    >>>
    >>> # Get analyzers for PE files
    >>> pe_analyzers = registry.get_analyzers_for_format("PE")
    >>> for name, analyzer_class in pe_analyzers.items():
    ...     print(f"{name}: {analyzer_class.__name__}")
    >>>
    >>> # Get only hashing analyzers
    >>> hashers = registry.get_by_category(AnalyzerCategory.HASHING)
    >>>
    >>> # Get required analyzers
    >>> required = registry.get_required_analyzers()

    Custom registry configuration:

    >>> from r2inspect.registry import AnalyzerRegistry, AnalyzerCategory
    >>> from r2inspect.modules import PEAnalyzer, SSDeepAnalyzer
    >>>
    >>> # Create custom registry
    >>> custom_registry = AnalyzerRegistry()
    >>>
    >>> # Register only specific analyzers
    >>> custom_registry.register(
    ...     name="pe_analyzer",
    ...     analyzer_class=PEAnalyzer,
    ...     category=AnalyzerCategory.FORMAT,
    ...     file_formats={"PE", "PE32", "PE32+"},
    ...     required=True
    ... )
    >>>
    >>> custom_registry.register(
    ...     name="ssdeep",
    ...     analyzer_class=SSDeepAnalyzer,
    ...     category=AnalyzerCategory.HASHING,
    ...     required=False
    ... )

    Format-specific registry:

    >>> from r2inspect.registry import get_format_specific_analyzers
    >>>
    >>> # Get only ELF-compatible analyzers
    >>> elf_registry = get_format_specific_analyzers("ELF")
    >>> for analyzer_info in elf_registry.list_analyzers():
    ...     print(f"{analyzer_info['name']}: {analyzer_info['description']}")

    Category-specific registry:

    >>> from r2inspect.registry import get_category_registry, AnalyzerCategory
    >>>
    >>> # Get only security analyzers
    >>> security_registry = get_category_registry(AnalyzerCategory.SECURITY)
    >>> for name in security_registry:
    ...     metadata = security_registry.get_metadata(name)
    ...     print(f"{name}: {metadata.description}")
"""

from .analyzer_registry import AnalyzerCategory, AnalyzerMetadata, AnalyzerRegistry
from .default_registry import (
    create_default_registry,
    get_category_registry,
    get_format_specific_analyzers,
    get_minimal_registry,
)

__all__ = [
    # Core registry classes
    "AnalyzerRegistry",
    "AnalyzerMetadata",
    "AnalyzerCategory",
    # Registry factory functions
    "create_default_registry",
    "get_format_specific_analyzers",
    "get_minimal_registry",
    "get_category_registry",
]

__version__ = "1.0.0"
