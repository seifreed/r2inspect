#!/usr/bin/env python3
"""Default analyzer registry configuration."""

from collections.abc import Callable

from ..infrastructure.logging import get_logger
from .analyzer_registry import AnalyzerCategory, AnalyzerMetadata, AnalyzerRegistry
from .default_registry_data import ANALYZERS, ELF_FORMATS, MACHO_FORMATS, PE_FORMATS
from .default_registry_support import create_default_registry_impl, filter_registry_impl

logger = get_logger(__name__)

_ANALYZERS = ANALYZERS


def create_default_registry() -> AnalyzerRegistry:
    """Create and configure the default analyzer registry."""
    return create_default_registry_impl()


def _filter_registry(predicate: Callable[[AnalyzerMetadata], bool]) -> AnalyzerRegistry:
    return filter_registry_impl(predicate, create_default_registry)


def get_format_specific_analyzers(file_format: str) -> AnalyzerRegistry:
    """Create a registry containing only analyzers for a specific file format."""
    return _filter_registry(lambda metadata: metadata.supports_format(file_format))


def get_minimal_registry() -> AnalyzerRegistry:
    """Create a registry with only required analyzers."""
    return _filter_registry(lambda metadata: metadata.required)


def get_category_registry(category: AnalyzerCategory) -> AnalyzerRegistry:
    """Create a registry containing analyzers from a specific category."""
    return _filter_registry(lambda metadata: metadata.category == category)
