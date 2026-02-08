import os
from types import SimpleNamespace

import pytest

from r2inspect.abstractions.base_analyzer import BaseAnalyzer
from r2inspect.registry.analyzer_registry import (
    AnalyzerCategory,
    AnalyzerMetadata,
    AnalyzerRegistry,
)


class DemoAnalyzer(BaseAnalyzer):
    def analyze(self):
        return {"ok": True}

    def get_category(self) -> str:
        return "format"

    def get_supported_formats(self) -> set[str]:
        return {"PE", "ELF"}

    def get_description(self) -> str:
        return "demo"


class BadAnalyzer:
    pass


def test_analyzer_metadata_validation_and_format_support():
    meta = AnalyzerMetadata(
        name="demo",
        analyzer_class=DemoAnalyzer,
        category=AnalyzerCategory.FORMAT,
        file_formats={"PE"},
    )
    assert meta.supports_format("pe") is True
    assert meta.supports_format("elf") is False
    assert meta.to_dict()["category"] == "format"

    with pytest.raises(ValueError):
        AnalyzerMetadata(name="", analyzer_class=DemoAnalyzer, category=AnalyzerCategory.FORMAT)

    with pytest.raises(ValueError):
        AnalyzerMetadata(name="demo", analyzer_class=None, category=AnalyzerCategory.FORMAT)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        AnalyzerMetadata(name="demo", analyzer_class=DemoAnalyzer, category="bad")  # type: ignore[arg-type]


def test_registry_base_analyzer_and_auto_extract(monkeypatch):
    registry = AnalyzerRegistry(lazy_loading=False)
    assert registry.is_base_analyzer(DemoAnalyzer) is True
    assert registry.is_base_analyzer(BadAnalyzer) is False
    assert registry.is_base_analyzer(123) is False

    metadata = registry.extract_metadata_from_class(DemoAnalyzer)
    assert metadata["name"] == "demo"
    assert metadata["category"] == "format"

    registry.register(name="demo", analyzer_class=DemoAnalyzer, required=True)
    assert registry.is_registered("demo") is True

    klass = registry.get_analyzer_class("demo")
    assert klass is DemoAnalyzer

    analyzers = registry.get_analyzers_for_format("ELF")
    assert "demo" in analyzers

    required = registry.get_required_analyzers()
    optional = registry.get_optional_analyzers()
    assert "demo" in required
    assert "demo" not in optional

    by_cat = registry.get_by_category(AnalyzerCategory.FORMAT)
    assert "demo" in by_cat

    listed = registry.list_analyzers()
    assert any(item["name"] == "demo" for item in listed)

    assert registry.get_dependencies("demo") == set()

    assert registry.unregister("demo") is True
    assert registry.unregister("missing") is False


def test_registry_validate_analyzer_and_category_parse():
    registry = AnalyzerRegistry(lazy_loading=False)

    is_valid, error = registry.validate_analyzer("bad")
    assert is_valid is False and error

    class AbstractBase(BaseAnalyzer):
        pass

    is_valid2, error2 = registry.validate_analyzer(AbstractBase)
    assert is_valid2 is False
    assert "analyze" in (error2 or "")

    class NoInit:
        def analyze(self):
            return {}

    is_valid3, error3 = registry.validate_analyzer(NoInit)
    assert is_valid3 is True
    assert error3 is None

    assert registry._parse_category("format") == AnalyzerCategory.FORMAT

    with pytest.raises(ValueError):
        registry._parse_category("bad")

    with pytest.raises(TypeError):
        registry._parse_category(123)


def test_registry_lazy_registration_and_fallback(monkeypatch):
    registry = AnalyzerRegistry(lazy_loading=True)

    registry.register(
        name="lazy",
        module_path="r2inspect.schemas.base",
        class_name="AnalysisResultBase",
        category=AnalyzerCategory.METADATA,
        description="lazy",
    )
    klass = registry.get_analyzer_class("lazy")
    assert klass is not None

    registry2 = AnalyzerRegistry(lazy_loading=False)
    registry2.register(
        name="lazy",
        module_path="r2inspect.schemas.base",
        class_name="AnalysisResultBase",
        category=AnalyzerCategory.METADATA,
        description="lazy",
    )
    klass2 = registry2.get_analyzer_class("lazy")
    assert klass2.__name__ == "AnalysisResultBase"

    with pytest.raises(ValueError):
        registry2.register(
            name="bad", module_path="x", class_name=None, category=AnalyzerCategory.METADATA
        )


def test_registry_execution_order_and_cycles():
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(name="a", analyzer_class=DemoAnalyzer, category=AnalyzerCategory.FORMAT)
    registry.register(
        name="b", analyzer_class=DemoAnalyzer, category=AnalyzerCategory.FORMAT, dependencies={"a"}
    )
    registry.register(
        name="c", analyzer_class=DemoAnalyzer, category=AnalyzerCategory.FORMAT, dependencies={"b"}
    )

    order = registry.resolve_execution_order(["a", "b", "c"])
    assert order.index("a") < order.index("b") < order.index("c")

    registry._analyzers["a"].dependencies.add("c")
    with pytest.raises(ValueError):
        registry.resolve_execution_order(["a", "b", "c"])

    with pytest.raises(KeyError):
        registry.resolve_execution_order(["missing"])


def test_registry_entry_points(monkeypatch):
    registry = AnalyzerRegistry(lazy_loading=False)

    class EP:
        def __init__(self, name, obj):
            self.name = name
            self._obj = obj

        def load(self):
            return self._obj

    def provider(reg: AnalyzerRegistry):
        reg.register(name="prov", analyzer_class=DemoAnalyzer, category=AnalyzerCategory.FORMAT)

    eps = [EP("provider", provider), EP("class", DemoAnalyzer), EP("bad", 123)]

    monkeypatch.setattr(
        "r2inspect.registry.analyzer_registry.entry_points",
        lambda: SimpleNamespace(select=lambda group=None: eps),
    )

    loaded = registry.load_entry_points()
    assert loaded == 2
    assert registry.is_registered("prov") is True

    registry.clear()
    assert len(registry) == 0
