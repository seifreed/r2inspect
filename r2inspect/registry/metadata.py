#!/usr/bin/env python3
"""Analyzer metadata model."""

from dataclasses import dataclass
from typing import Any

from .categories import AnalyzerCategory


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
        }
