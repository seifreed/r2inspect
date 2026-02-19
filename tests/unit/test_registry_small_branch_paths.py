#!/usr/bin/env python3
"""Branch path tests for registry modules."""

from __future__ import annotations

import pytest

from r2inspect.registry.analyzer_registry import AnalyzerCategory, AnalyzerRegistry
from r2inspect.registry.metadata import AnalyzerMetadata
from r2inspect.registry.metadata_extraction import auto_extract_metadata, extract_metadata_from_class, parse_category


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class DummyAnalyzer:
    def __init__(self, adapter=None, **_kw):
        pass

    def analyze(self):
        return {}


# ---------------------------------------------------------------------------
# registry_queries.py
# ---------------------------------------------------------------------------

def test_get_analyzer_class_returns_none_for_unknown() -> None:
    """get_analyzer_class returns None when name is not registered."""
    registry = AnalyzerRegistry(lazy_loading=False)
    result = registry.get_analyzer_class("nonexistent_analyzer")
    assert result is None


def test_get_analyzers_for_format_skips_unsupported_format() -> None:
    """get_analyzers_for_format excludes analyzers whose format does not match."""
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        "dummy",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.FORMAT,
        file_formats={"ELF"},
        auto_extract=False,
    )
    result = registry.get_analyzers_for_format("PE")
    assert "dummy" not in result


def test_get_by_category_skips_wrong_category() -> None:
    """get_by_category excludes analyzers in a different category."""
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        "dummy_hash",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.HASHING,
        auto_extract=False,
    )
    result = registry.get_by_category(AnalyzerCategory.FORMAT)
    assert "dummy_hash" not in result


def test_get_required_analyzers_skips_optional() -> None:
    """get_required_analyzers excludes optional (required=False) analyzers."""
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        "opt_analyzer",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.FORMAT,
        required=False,
        auto_extract=False,
    )
    result = registry.get_required_analyzers()
    assert "opt_analyzer" not in result


def test_get_optional_analyzers_returns_optional_entries() -> None:
    """get_optional_analyzers returns analyzers registered as optional."""
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        "opt_analyzer2",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.FORMAT,
        required=False,
        auto_extract=False,
    )
    result = registry.get_optional_analyzers()
    assert "opt_analyzer2" in result
    assert result["opt_analyzer2"] is DummyAnalyzer


def test_resolve_execution_order_with_dependency_appends_to_queue() -> None:
    """resolve_execution_order handles dependency graph and appends to queue correctly."""
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        "dep_a",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.FORMAT,
        auto_extract=False,
    )
    registry.register(
        "dep_b",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.FORMAT,
        dependencies={"dep_a"},
        auto_extract=False,
    )
    order = registry.resolve_execution_order(["dep_a", "dep_b"])
    assert order.index("dep_a") < order.index("dep_b")


# ---------------------------------------------------------------------------
# metadata_extraction.py
# ---------------------------------------------------------------------------

def test_extract_metadata_from_class_raises_for_non_base_analyzer() -> None:
    """extract_metadata_from_class raises ValueError for non-BaseAnalyzer class."""
    registry = AnalyzerRegistry(lazy_loading=False)

    with pytest.raises(ValueError, match="does not inherit from BaseAnalyzer"):
        extract_metadata_from_class(
            DummyAnalyzer,
            is_base_analyzer=registry.is_base_analyzer,
        )


def test_auto_extract_metadata_fills_category_when_none() -> None:
    """auto_extract_metadata extracts category when category is None and class is BaseAnalyzer."""
    from r2inspect.modules.pe_analyzer import PEAnalyzer

    registry = AnalyzerRegistry(lazy_loading=False)
    category, file_formats, description = auto_extract_metadata(
        PEAnalyzer,
        name="pe",
        category=None,
        file_formats=None,
        description="",
        auto_extract=True,
        is_base_analyzer=registry.is_base_analyzer,
    )
    assert category is not None
    assert file_formats is not None


# ---------------------------------------------------------------------------
# metadata.py
# ---------------------------------------------------------------------------

def test_supports_format_returns_true_for_matching_format() -> None:
    """AnalyzerMetadata.supports_format returns True when format matches."""
    meta = AnalyzerMetadata(
        name="test",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.FORMAT,
        file_formats={"PE", "ELF"},
    )
    assert meta.supports_format("PE") is True


def test_supports_format_returns_false_for_non_matching_format() -> None:
    """AnalyzerMetadata.supports_format returns False when format does not match."""
    meta = AnalyzerMetadata(
        name="test",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.FORMAT,
        file_formats={"ELF"},
    )
    assert meta.supports_format("PE") is False


def test_supports_format_returns_true_for_empty_file_formats() -> None:
    """AnalyzerMetadata.supports_format returns True when file_formats is empty (all formats)."""
    meta = AnalyzerMetadata(
        name="test",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.FORMAT,
        file_formats=set(),
    )
    assert meta.supports_format("ANYTHING") is True
