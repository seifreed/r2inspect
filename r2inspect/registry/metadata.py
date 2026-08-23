#!/usr/bin/env python3
"""Analyzer metadata model."""

from dataclasses import dataclass
from typing import Any

from .categories import AnalyzerCategory


@dataclass(frozen=True, slots=True)
class AnalyzerSpec:
    """Declarative analyzer metadata safe to inspect without construction."""

    id: str
    version: str
    category: AnalyzerCategory
    formats: frozenset[str] = frozenset()
    architectures: frozenset[str] = frozenset()
    dependencies: frozenset[str] = frozenset()
    output_schema: str | None = None
    description: str = ""
    required: bool = False

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("Analyzer id cannot be empty")
        if not self.version:
            raise ValueError("Analyzer version cannot be empty")
        if not isinstance(self.category, AnalyzerCategory):
            raise TypeError("Analyzer category must be an AnalyzerCategory")


@dataclass(slots=True)
class AnalyzerMetadata:
    """Metadata for a registered analyzer."""

    name: str
    analyzer_class: type
    category: AnalyzerCategory
    file_formats: set[str] | None = None
    required: bool = False
    dependencies: set[str] | None = None
    description: str = ""
    version: str | None = None
    architectures: set[str] | None = None
    output_schema: str | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("Analyzer name cannot be empty")
        if self.analyzer_class is None:
            raise ValueError("Analyzer class cannot be None")
        if not isinstance(self.category, AnalyzerCategory):
            raise TypeError(f"Category must be AnalyzerCategory, got {type(self.category)}")
        if self.file_formats is None:
            self.file_formats = set()
        if self.dependencies is None:
            self.dependencies = set()
        if self.architectures is None:
            self.architectures = set()

    def supports_format(self, file_format: str) -> bool:
        """
        Check if analyzer supports a specific file format.

        Args:
            file_format: File format identifier (e.g., "PE", "ELF")

        Returns:
            True if analyzer supports the format or supports all formats
        """
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
            "file_formats": list(self.file_formats or []),
            "required": self.required,
            "dependencies": list(self.dependencies or []),
            "description": self.description,
            "version": self.version,
            "architectures": list(self.architectures or []),
            "output_schema": self.output_schema,
        }
