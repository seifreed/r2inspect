from __future__ import annotations

from r2inspect.registry.analyzer_registry import AnalyzerCategory, AnalyzerRegistry


class _DummyAnalyzer:
    @staticmethod
    def get_supported_formats() -> set[str]:
        return {"PE"}

    @staticmethod
    def get_category() -> AnalyzerCategory:
        return AnalyzerCategory.METADATA

    @staticmethod
    def get_description() -> str:
        return "dummy analyzer"


def test_analyzer_registry_register_and_query():
    registry = AnalyzerRegistry()
    registry.register(
        name="dummy",
        analyzer_class=_DummyAnalyzer,
        category=AnalyzerCategory.METADATA,
        file_formats={"PE"},
        required=True,
        description="dummy analyzer",
        auto_extract=False,
    )

    meta = registry.get_metadata("dummy")
    assert meta is not None
    assert meta.name == "dummy"
    assert meta.category == AnalyzerCategory.METADATA

    cls = registry.get_analyzer_class("dummy")
    assert cls is _DummyAnalyzer

    by_category = registry.get_by_category(AnalyzerCategory.METADATA)
    assert "dummy" in by_category

    required = registry.get_required_analyzers()
    assert "dummy" in required


def test_analyzer_registry_lazy_registration():
    registry = AnalyzerRegistry()
    registry.register(
        name="pe_lazy",
        module_path="r2inspect.modules.pe_analyzer",
        class_name="PEAnalyzer",
        category=AnalyzerCategory.FORMAT,
        file_formats={"PE"},
        required=False,
        description="PE format analyzer",
    )

    cls = registry.get_analyzer_class("pe_lazy")
    assert cls is not None
    assert cls.__name__ == "PEAnalyzer"
