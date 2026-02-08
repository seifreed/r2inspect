from __future__ import annotations

from r2inspect.registry.analyzer_registry import AnalyzerCategory
from r2inspect.registry.default_registry import (
    create_default_registry,
    get_category_registry,
    get_format_specific_analyzers,
    get_minimal_registry,
)


def test_default_registry_builds() -> None:
    registry = create_default_registry()
    assert len(registry) > 0
    assert registry.is_registered("pe_analyzer")


def test_default_registry_filters() -> None:
    pe_registry = get_format_specific_analyzers("PE")
    assert "pe_analyzer" in pe_registry

    minimal = get_minimal_registry()
    assert minimal.get_required_analyzers()

    category_registry = get_category_registry(AnalyzerCategory.METADATA)
    assert category_registry.get_by_category(AnalyzerCategory.METADATA)
