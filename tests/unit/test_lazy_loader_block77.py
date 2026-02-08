from __future__ import annotations

import pytest

from r2inspect.lazy_loader import LazyAnalyzerLoader, get_global_lazy_loader


def test_register_and_get_analyzer_class():
    loader = LazyAnalyzerLoader()
    loader.register("config", "r2inspect.config", "Config", category="core")

    assert loader.is_registered("config") is True
    assert loader.is_loaded("config") is False

    cls = loader.get_analyzer_class("config")
    assert cls.__name__ == "Config"
    assert loader.is_loaded("config") is True

    # Cache hit
    cls2 = loader.get_analyzer_class("config")
    assert cls2 is cls


def test_register_errors_and_overwrite():
    loader = LazyAnalyzerLoader()
    with pytest.raises(ValueError):
        loader.register("", "r2inspect.config", "Config")

    with pytest.raises(ValueError):
        loader.register("x", "", "Config")

    loader.register("x", "r2inspect.config", "Config")
    loader.register("x", "r2inspect.config", "Config")


def test_unload_unregister_and_clear():
    loader = LazyAnalyzerLoader()
    loader.register("config", "r2inspect.config", "Config")
    loader.get_analyzer_class("config")
    assert loader.unload("config") is True
    assert loader.is_loaded("config") is False

    assert loader.unregister("config") is True
    assert loader.is_registered("config") is False

    loader.register("config", "r2inspect.config", "Config")
    loader.get_analyzer_class("config")
    assert loader.clear_cache() == 1


def test_preload_and_categories():
    loader = LazyAnalyzerLoader()
    loader.register("config", "r2inspect.config", "Config", category="core")
    loader.register("config2", "r2inspect.config", "Config", category="core")

    results = loader.preload("config", "missing")
    assert results["config"] is True
    assert results["missing"] is True

    cat_results = loader.preload_category("core")
    assert cat_results["config"] is True
    assert cat_results["config2"] is True


def test_stats_and_repr_and_list_registered():
    loader = LazyAnalyzerLoader()
    loader.register("config", "r2inspect.config", "Config", category="core", formats={"PE"})
    assert len(loader) == 1
    assert "config" in loader

    cls = loader.get_analyzer_class("config")
    assert cls is not None

    stats = loader.get_stats()
    assert stats["registered"] == 1
    assert stats["loaded"] == 1
    assert stats["cache_hits"] >= 0

    listed = loader.list_registered()
    assert listed["config"]["category"] == "core"
    assert listed["config"]["formats"] == ["PE"]
    assert listed["config"]["loaded"] is True

    assert "LazyAnalyzerLoader" in repr(loader)


def test_missing_module_and_class_errors():
    loader = LazyAnalyzerLoader()
    loader.register("badmod", "r2inspect.missing_module", "Config")
    with pytest.raises(ImportError):
        loader.get_analyzer_class("badmod")

    loader.register("badclass", "r2inspect.config", "MissingClass")
    with pytest.raises(AttributeError):
        loader.get_analyzer_class("badclass")


def test_global_lazy_loader_singleton():
    loader = get_global_lazy_loader()
    loader2 = get_global_lazy_loader()
    assert loader is loader2
