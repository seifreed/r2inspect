import types

import pytest

from r2inspect.lazy_loader import LazyAnalyzerLoader


def test_lazy_loader_register_and_load():
    loader = LazyAnalyzerLoader()
    loader.register("json_decoder", "json", "JSONDecoder", category="test")
    cls = loader.get_analyzer_class("json_decoder")
    assert cls is not None
    assert cls.__name__ == "JSONDecoder"
    assert loader.is_loaded("json_decoder") is True


def test_lazy_loader_unload_and_unregister():
    loader = LazyAnalyzerLoader()
    loader.register("decoder", "json", "JSONDecoder")
    assert loader.get_analyzer_class("decoder") is not None
    assert loader.unload("decoder") is True
    assert loader.is_loaded("decoder") is False
    assert loader.unregister("decoder") is True
    assert loader.is_registered("decoder") is False


def test_lazy_loader_preload_category():
    loader = LazyAnalyzerLoader()
    loader.register("dec1", "json", "JSONDecoder", category="cat")
    loader.register("enc1", "json", "JSONEncoder", category="cat")
    results = loader.preload_category("cat")
    assert results["dec1"] is True
    assert results["enc1"] is True


def test_lazy_loader_stats():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    _ = loader.get_analyzer_class("dec")
    stats = loader.get_stats()
    assert stats["registered"] == 1
    assert stats["loaded"] == 1
    assert stats["cache_misses"] >= 1
