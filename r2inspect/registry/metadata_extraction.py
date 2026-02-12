#!/usr/bin/env python3
"""Helpers for analyzer metadata extraction."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from .categories import AnalyzerCategory


def parse_category(category_value: Any) -> AnalyzerCategory:
    """
    Parse category value into AnalyzerCategory enum.

    Handles both string and AnalyzerCategory enum values.
    """
    if isinstance(category_value, AnalyzerCategory):
        return category_value

    if isinstance(category_value, str):
        category_str = category_value.lower()
        for cat in AnalyzerCategory:
            if cat.value == category_str:
                return cat
        raise ValueError(
            f"Unknown category string: {category_value}. "
            f"Valid categories: {[c.value for c in AnalyzerCategory]}"
        )

    raise TypeError(f"Category must be AnalyzerCategory enum or string, got {type(category_value)}")


def extract_metadata_from_class(
    analyzer_class: type,
    *,
    is_base_analyzer: Callable[[type], bool],
    name: str | None = None,
) -> dict[str, Any]:
    """
    Extract metadata from a BaseAnalyzer class.

    Creates a temporary instance (with None parameters) to call metadata
    methods and extract analyzer information.
    """
    if not is_base_analyzer(analyzer_class):
        raise ValueError(f"{analyzer_class.__name__} does not inherit from BaseAnalyzer")

    try:
        temp_instance = analyzer_class(adapter=None, config=None, filepath=None)
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
    except Exception as exc:
        raise RuntimeError(
            f"Failed to extract metadata from {analyzer_class.__name__}: {exc}"
        ) from exc


def auto_extract_metadata(
    analyzer_class: type,
    *,
    name: str,
    category: AnalyzerCategory | str | None,
    file_formats: set[str] | None,
    description: str,
    auto_extract: bool,
    is_base_analyzer: Callable[[type], bool],
) -> tuple[AnalyzerCategory | str | None, set[str] | None, str]:
    """Auto-extract metadata from BaseAnalyzer subclasses when enabled."""
    if not auto_extract or not is_base_analyzer(analyzer_class):
        return category, file_formats, description

    try:
        extracted = extract_metadata_from_class(
            analyzer_class, is_base_analyzer=is_base_analyzer, name=name
        )
        if category is None:
            category = parse_category(extracted["category"])
        if file_formats is None:
            file_formats = extracted["formats"]
        if not description:
            description = extracted["description"]
    except Exception as exc:
        logging.getLogger(__name__).warning(
            f"Auto-extraction failed for {analyzer_class.__name__}: {exc}. "
            "Using provided metadata."
        )
    return category, file_formats, description
