from __future__ import annotations

import pytest

from r2inspect.abstractions.base_analyzer import BaseAnalyzer
from r2inspect.registry.analyzer_registry import AnalyzerCategory, AnalyzerRegistry


class SampleAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict:
        return {"ok": True}

    def get_category(self) -> str:
        return "metadata"

    def get_supported_formats(self) -> set[str]:
        return {"PE"}

    def get_description(self) -> str:
        return "Sample analyzer"


class BadAnalyzer(BaseAnalyzer):
    pass


def test_extract_metadata_from_class():
    registry = AnalyzerRegistry(lazy_loading=False)
    meta = registry.extract_metadata_from_class(SampleAnalyzer)
    assert meta["name"] == "sample"
    assert meta["category"] == "metadata"
    assert "PE" in meta["formats"]
    assert meta["description"] == "Sample analyzer"

    with pytest.raises(RuntimeError):
        registry.extract_metadata_from_class(BadAnalyzer)


def test_parse_category_and_validate_analyzer():
    registry = AnalyzerRegistry(lazy_loading=False)
    assert registry._parse_category("metadata") == AnalyzerCategory.METADATA

    with pytest.raises(ValueError):
        registry._parse_category("nope")

    with pytest.raises(TypeError):
        registry._parse_category(123)

    ok, err = registry.validate_analyzer(123)  # type: ignore[arg-type]
    assert ok is False
    assert "class" in err

    ok, err = registry.validate_analyzer(BadAnalyzer)
    assert ok is False
    assert "analyze" in err


def test_register_from_instance():
    registry = AnalyzerRegistry(lazy_loading=False)
    instance = SampleAnalyzer(adapter=None, config=None, filepath=None)
    registry.register_from_instance(instance, required=True)
    assert registry.is_registered("sample") is True
    meta = registry.get_metadata("sample")
    assert meta is not None
    assert meta.required is True
