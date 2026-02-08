from __future__ import annotations

import os

import pytest

from r2inspect.registry.analyzer_registry import (
    AnalyzerCategory,
    AnalyzerMetadata,
    AnalyzerRegistry,
)


class DummyAnalyzer:
    """Minimal analyzer used for registry tests."""


class DepAnalyzer:
    """Analyzer used as dependency."""


def test_analyzer_metadata_validation():
    with pytest.raises(ValueError):
        AnalyzerMetadata("", DummyAnalyzer, AnalyzerCategory.FORMAT)

    with pytest.raises(ValueError):
        AnalyzerMetadata("x", None, AnalyzerCategory.FORMAT)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        AnalyzerMetadata("x", DummyAnalyzer, "format")  # type: ignore[arg-type]


def test_registry_basic_register_and_query():
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        name="dummy",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.METADATA,
        file_formats={"PE"},
        required=True,
        dependencies={"dep"},
        description="demo",
    )
    assert registry.is_registered("dummy") is True
    meta = registry.get_metadata("dummy")
    assert meta is not None
    assert meta.supports_format("pe") is True
    assert meta.description == "demo"

    registry.register(
        name="dep",
        analyzer_class=DepAnalyzer,
        category=AnalyzerCategory.METADATA,
        file_formats=set(),
        required=False,
        dependencies=set(),
        description="dep",
    )

    by_cat = registry.get_by_category(AnalyzerCategory.METADATA)
    assert "dummy" in by_cat

    required = registry.get_required_analyzers()
    assert "dummy" in required
    optional = registry.get_optional_analyzers()
    assert "dep" in optional


def test_registry_unregister_and_len():
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        name="dummy",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.METADATA,
    )
    assert len(registry) == 1
    assert registry.unregister("dummy") is True
    assert registry.unregister("missing") is False
    assert len(registry) == 0


def test_registry_execution_order():
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        name="dep",
        analyzer_class=DepAnalyzer,
        category=AnalyzerCategory.METADATA,
    )
    registry.register(
        name="dummy",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.METADATA,
        dependencies={"dep"},
    )
    order = registry.resolve_execution_order(["dummy", "dep"])
    assert order[0] == "dep"
    assert order[-1] == "dummy"


def test_registry_env_lazy_loading(monkeypatch):
    monkeypatch.setenv("R2INSPECT_LAZY_LOADING", "0")
    registry = AnalyzerRegistry(lazy_loading=None)
    assert registry._lazy_loading is False
