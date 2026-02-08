from __future__ import annotations

from r2inspect.registry.analyzer_registry import AnalyzerCategory, AnalyzerRegistry
from r2inspect.registry.default_registry import create_default_registry


class DummyAnalyzer:
    pass


def test_registry_register_and_query():
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        name="dummy",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.METADATA,
        file_formats={"PE"},
        required=True,
        dependencies={"pe_analyzer"},
        description="dummy analyzer",
    )

    meta = registry.get_metadata("dummy")
    assert meta is not None
    assert meta.name == "dummy"
    assert meta.required is True
    assert meta.supports_format("PE") is True
    assert "pe_analyzer" in meta.dependencies

    assert registry.get_analyzer_class("dummy") is DummyAnalyzer
    assert "dummy" in registry.get_required_analyzers()
    assert "dummy" in registry.get_by_category(AnalyzerCategory.METADATA)


def test_default_registry_contains_core_analyzers():
    registry = create_default_registry()
    assert registry.get_analyzer_class("pe_analyzer") is not None
    assert registry.get_analyzer_class("elf_analyzer") is not None
    assert registry.get_analyzer_class("macho_analyzer") is not None
