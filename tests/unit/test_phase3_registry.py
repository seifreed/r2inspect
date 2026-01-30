from __future__ import annotations

import pytest

from r2inspect.abstractions.base_analyzer import BaseAnalyzer
from r2inspect.registry.analyzer_registry import (
    AnalyzerCategory,
    AnalyzerMetadata,
    AnalyzerRegistry,
)


class SampleAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, object]:
        return {"available": True}

    def get_category(self) -> str:
        return "format"

    def get_supported_formats(self) -> set[str]:
        return {"PE"}

    def get_description(self) -> str:
        return "Sample analyzer"


class AnotherAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, object]:
        return {"available": True}

    def get_category(self) -> str:
        return "metadata"


def test_analyzer_metadata_supports_format() -> None:
    meta = AnalyzerMetadata(
        name="sample",
        analyzer_class=SampleAnalyzer,
        category=AnalyzerCategory.FORMAT,
        file_formats={"PE"},
    )
    assert meta.supports_format("PE")
    assert not meta.supports_format("ELF")
    assert meta.to_dict()["category"] == "format"


def test_registry_register_and_query() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        name="sample",
        analyzer_class=SampleAnalyzer,
        required=True,
    )
    registry.register(
        name="another",
        analyzer_class=AnotherAnalyzer,
        required=False,
        dependencies={"sample"},
    )

    assert registry.get_analyzer_class("sample") is SampleAnalyzer
    assert registry.get_metadata("sample").description == "Sample analyzer"
    assert "sample" in registry.get_analyzers_for_format("PE")
    assert "another" in registry.get_analyzers_for_format("ELF")

    format_analyzers = registry.get_by_category(AnalyzerCategory.FORMAT)
    assert "sample" in format_analyzers

    required = registry.get_required_analyzers()
    optional = registry.get_optional_analyzers()
    assert "sample" in required
    assert "another" in optional

    deps = registry.get_dependencies("another")
    assert deps == {"sample"}


def test_registry_unregister() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        name="sample",
        analyzer_class=SampleAnalyzer,
        category=AnalyzerCategory.FORMAT,
    )
    assert registry.unregister("sample") is True
    assert registry.unregister("sample") is False


def test_registry_register_from_instance() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    instance = SampleAnalyzer()
    registry.register_from_instance(instance, required=True)
    assert registry.get_analyzer_class("sample") is SampleAnalyzer


def test_registry_invalid_registration() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    with pytest.raises(ValueError):
        registry.register(name="bad")

    with pytest.raises(ValueError):
        registry.register(
            name="bad",
            analyzer_class=SampleAnalyzer,
            module_path="r2inspect.modules.pe_analyzer",
            class_name="PEAnalyzer",
        )

    with pytest.raises(ValueError):
        registry.register_from_instance(object())
