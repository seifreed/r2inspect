from __future__ import annotations

import pytest

from r2inspect.lazy_loader import LazyAnalyzerLoader


def test_lazy_loader_register_and_load() -> None:
    loader = LazyAnalyzerLoader()
    loader.register("base", "r2inspect.schemas.base", "AnalysisResultBase", category="schemas")
    assert loader.is_registered("base") is True
    assert loader.is_loaded("base") is False
    cls = loader.get_analyzer_class("base")
    assert cls is not None
    assert loader.is_loaded("base") is True
    cls2 = loader.get_analyzer_class("base")
    assert cls2 is cls
    stats = loader.get_stats()
    assert stats["registered"] == 1
    assert stats["loaded"] == 1
    assert stats["cache_hits"] >= 1


def test_lazy_loader_validation_and_unload_unregister() -> None:
    loader = LazyAnalyzerLoader()
    with pytest.raises(ValueError):
        loader.register("", "r2inspect.schemas.base", "AnalysisResultBase")
    with pytest.raises(ValueError):
        loader.register("bad", "", "AnalysisResultBase")

    loader.register("base", "r2inspect.schemas.base", "AnalysisResultBase")
    assert loader.unload("base") is False
    loader.get_analyzer_class("base")
    assert loader.unload("base") is True
    assert loader.is_loaded("base") is False
    assert loader.unregister("base") is True
    assert loader.unregister("base") is False


def test_lazy_loader_preload_and_list() -> None:
    loader = LazyAnalyzerLoader()
    loader.register("base", "r2inspect.schemas.base", "AnalysisResultBase", category="schemas")
    loader.register("hash", "r2inspect.schemas.hashing", "HashAnalysisResult", category="schemas")
    loader.register("bad", "r2inspect.nope", "Nope", category="schemas")
    results = loader.preload("base", "bad")
    assert results["base"] is True
    assert results["bad"] is False
    cat_results = loader.preload_category("schemas")
    assert cat_results["base"] is True
    assert cat_results["hash"] is True
    listed = loader.list_registered()
    assert "base" in listed
    assert listed["base"]["loaded"] is True
    cleared = loader.clear_cache()
    assert cleared >= 1
    assert len(loader) == 3
    assert "base" in loader
