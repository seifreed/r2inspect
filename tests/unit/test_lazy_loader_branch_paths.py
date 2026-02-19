#!/usr/bin/env python3
"""Branch-path tests for r2inspect/lazy_loader.py - real objects only."""

from __future__ import annotations

import threading

import pytest

from r2inspect.lazy_loader import (
    LazyAnalyzerLoader,
    LazyAnalyzerSpec,
    _init_loader_stats,
    get_global_lazy_loader,
)


# ---------------------------------------------------------------------------
# LazyAnalyzerSpec dataclass
# ---------------------------------------------------------------------------


def test_lazy_analyzer_spec_with_all_fields():
    spec = LazyAnalyzerSpec(
        module_path="json",
        class_name="JSONDecoder",
        category="parsing",
        formats={"JSON"},
        metadata={"version": "1"},
    )
    assert spec.module_path == "json"
    assert spec.class_name == "JSONDecoder"
    assert spec.category == "parsing"
    assert "JSON" in spec.formats
    assert spec.metadata["version"] == "1"


def test_lazy_analyzer_spec_default_fields():
    spec = LazyAnalyzerSpec(module_path="os", class_name="PathLike")
    assert spec.category is None
    assert spec.formats == set()
    assert spec.metadata == {}


# ---------------------------------------------------------------------------
# _init_loader_stats
# ---------------------------------------------------------------------------


def test_init_loader_stats_all_zero():
    stats = _init_loader_stats()
    assert stats["load_count"] == 0
    assert stats["cache_hits"] == 0
    assert stats["cache_misses"] == 0
    assert stats["failed_loads"] == 0
    assert stats["load_times"] == {}


# ---------------------------------------------------------------------------
# register validation paths
# ---------------------------------------------------------------------------


def test_register_empty_name_raises_value_error():
    loader = LazyAnalyzerLoader()
    with pytest.raises(ValueError, match="Analyzer name cannot be empty"):
        loader.register("", "json", "JSONDecoder")


def test_register_empty_module_path_raises_value_error():
    loader = LazyAnalyzerLoader()
    with pytest.raises(ValueError, match="Module path and class name are required"):
        loader.register("test", "", "JSONDecoder")


def test_register_empty_class_name_raises_value_error():
    loader = LazyAnalyzerLoader()
    with pytest.raises(ValueError, match="Module path and class name are required"):
        loader.register("test", "json", "")


def test_register_duplicate_same_path_no_warning_overwrites():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder", category="a")
    loader.register("dec", "json", "JSONDecoder", category="b")
    assert loader.is_registered("dec")


def test_register_duplicate_different_path_overwrites():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    loader.register("dec", "os", "PathLike")
    spec = loader._registry["dec"]
    assert spec.module_path == "os"
    assert spec.class_name == "PathLike"


def test_register_with_formats_and_metadata():
    loader = LazyAnalyzerLoader()
    loader.register(
        "test",
        "json",
        "JSONDecoder",
        category="fmt",
        formats={"PE", "ELF"},
        metadata={"author": "test"},
    )
    spec = loader._registry["test"]
    assert "PE" in spec.formats
    assert "ELF" in spec.formats
    assert spec.metadata["author"] == "test"


# ---------------------------------------------------------------------------
# get_analyzer_class - cache paths
# ---------------------------------------------------------------------------


def test_get_analyzer_class_not_registered_returns_none():
    loader = LazyAnalyzerLoader()
    assert loader.get_analyzer_class("nonexistent") is None


def test_get_analyzer_class_cache_miss_then_hit():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    assert loader._stats["cache_misses"] == 0

    cls = loader.get_analyzer_class("dec")
    assert cls is not None
    assert loader._stats["cache_misses"] == 1
    assert loader._stats["cache_hits"] == 0
    assert loader._stats["load_count"] == 1

    cls2 = loader.get_analyzer_class("dec")
    assert cls2 is cls
    assert loader._stats["cache_hits"] == 1
    assert loader._stats["cache_misses"] == 1


def test_get_analyzer_class_tracks_load_time():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    loader.get_analyzer_class("dec")
    assert "dec" in loader._stats["load_times"]
    assert loader._stats["load_times"]["dec"] > 0


def test_get_analyzer_class_import_error_tracked():
    loader = LazyAnalyzerLoader()
    loader.register("bad", "no.such.module.xyz", "SomeClass")
    with pytest.raises(ImportError):
        loader.get_analyzer_class("bad")
    assert loader._stats["failed_loads"] == 1


def test_get_analyzer_class_attribute_error_tracked():
    loader = LazyAnalyzerLoader()
    loader.register("bad", "os", "ClassThatDoesNotExist")
    with pytest.raises(AttributeError):
        loader.get_analyzer_class("bad")
    assert loader._stats["failed_loads"] == 1


def test_get_analyzer_class_correct_class_returned():
    import json as json_module

    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    cls = loader.get_analyzer_class("dec")
    assert cls is json_module.JSONDecoder


# ---------------------------------------------------------------------------
# is_loaded / is_registered
# ---------------------------------------------------------------------------


def test_is_loaded_false_before_load():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    assert loader.is_loaded("dec") is False


def test_is_loaded_true_after_load():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    loader.get_analyzer_class("dec")
    assert loader.is_loaded("dec") is True


def test_is_registered_true_and_false():
    loader = LazyAnalyzerLoader()
    assert loader.is_registered("x") is False
    loader.register("x", "os", "sep")
    assert loader.is_registered("x") is True


# ---------------------------------------------------------------------------
# unload
# ---------------------------------------------------------------------------


def test_unload_not_in_cache_returns_false():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    assert loader.unload("dec") is False


def test_unload_loaded_analyzer_returns_true():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    loader.get_analyzer_class("dec")
    assert loader.is_loaded("dec") is True
    assert loader.unload("dec") is True
    assert loader.is_loaded("dec") is False


def test_unload_preserves_registration():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    loader.get_analyzer_class("dec")
    loader.unload("dec")
    assert loader.is_registered("dec") is True


# ---------------------------------------------------------------------------
# unregister
# ---------------------------------------------------------------------------


def test_unregister_not_found_returns_false():
    loader = LazyAnalyzerLoader()
    assert loader.unregister("nonexistent") is False


def test_unregister_registered_only_returns_true():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    assert loader.unregister("dec") is True
    assert loader.is_registered("dec") is False


def test_unregister_registered_and_loaded_removes_both():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    loader.get_analyzer_class("dec")
    assert loader.is_loaded("dec") is True
    assert loader.unregister("dec") is True
    assert loader.is_registered("dec") is False
    assert loader.is_loaded("dec") is False


# ---------------------------------------------------------------------------
# preload
# ---------------------------------------------------------------------------


def test_preload_single_analyzer_success():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    results = loader.preload("dec")
    assert results == {"dec": True}
    assert loader.is_loaded("dec") is True


def test_preload_multiple_analyzers():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    loader.register("enc", "json", "JSONEncoder")
    results = loader.preload("dec", "enc")
    assert results["dec"] is True
    assert results["enc"] is True


def test_preload_failure_returns_false():
    loader = LazyAnalyzerLoader()
    loader.register("bad", "no.such.module.xyz", "Class")
    results = loader.preload("bad")
    assert results["bad"] is False


def test_preload_mixed_success_and_failure():
    loader = LazyAnalyzerLoader()
    loader.register("good", "json", "JSONDecoder")
    loader.register("bad", "no.such.module.xyz", "Class")
    results = loader.preload("good", "bad")
    assert results["good"] is True
    assert results["bad"] is False


# ---------------------------------------------------------------------------
# preload_category
# ---------------------------------------------------------------------------


def test_preload_category_loads_matching():
    loader = LazyAnalyzerLoader()
    loader.register("pe", "json", "JSONDecoder", category="format")
    loader.register("elf", "json", "JSONEncoder", category="format")
    loader.register("hash", "os", "sep", category="hashing")
    results = loader.preload_category("format")
    assert len(results) == 2
    assert results["pe"] is True
    assert results["elf"] is True
    assert "hash" not in results


def test_preload_category_no_matches_returns_empty():
    loader = LazyAnalyzerLoader()
    loader.register("pe", "json", "JSONDecoder", category="format")
    results = loader.preload_category("hashing")
    assert results == {}


# ---------------------------------------------------------------------------
# get_stats / clear_cache
# ---------------------------------------------------------------------------


def test_get_stats_returns_correct_structure():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    loader.get_analyzer_class("dec")
    stats = loader.get_stats()
    assert stats["registered"] == 1
    assert stats["loaded"] == 1
    assert stats["unloaded"] == 0
    assert stats["load_count"] == 1
    assert stats["cache_misses"] == 1
    assert stats["cache_hits"] == 0
    assert isinstance(stats["cache_hit_rate"], float)
    assert isinstance(stats["lazy_ratio"], float)
    assert isinstance(stats["load_times"], dict)


def test_get_stats_cache_hit_rate_after_repeated_access():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    loader.get_analyzer_class("dec")  # miss
    loader.get_analyzer_class("dec")  # hit
    loader.get_analyzer_class("dec")  # hit
    stats = loader.get_stats()
    assert stats["cache_hits"] == 2
    assert stats["cache_misses"] == 1
    assert stats["cache_hit_rate"] == pytest.approx(2 / 3)


def test_clear_cache_returns_count():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    loader.register("enc", "json", "JSONEncoder")
    loader.get_analyzer_class("dec")
    loader.get_analyzer_class("enc")
    count = loader.clear_cache()
    assert count == 2
    assert loader.is_loaded("dec") is False
    assert loader.is_loaded("enc") is False


def test_clear_cache_empty_returns_zero():
    loader = LazyAnalyzerLoader()
    assert loader.clear_cache() == 0


def test_stats_lazy_ratio_all_unloaded():
    loader = LazyAnalyzerLoader()
    loader.register("a", "json", "JSONDecoder")
    loader.register("b", "json", "JSONEncoder")
    stats = loader.get_stats()
    assert stats["lazy_ratio"] == 1.0


def test_stats_no_registered_returns_zero_lazy_ratio():
    loader = LazyAnalyzerLoader()
    stats = loader.get_stats()
    assert stats["lazy_ratio"] == 0.0
    assert stats["cache_hit_rate"] == 0.0


# ---------------------------------------------------------------------------
# list_registered
# ---------------------------------------------------------------------------


def test_list_registered_empty_loader():
    loader = LazyAnalyzerLoader()
    assert loader.list_registered() == {}


def test_list_registered_shows_loaded_status():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder", category="parsing", formats={"JSON"})
    registered = loader.list_registered()
    assert "dec" in registered
    assert registered["dec"]["loaded"] is False
    assert registered["dec"]["module_path"] == "json"
    assert registered["dec"]["class_name"] == "JSONDecoder"
    assert registered["dec"]["category"] == "parsing"
    assert "JSON" in registered["dec"]["formats"]

    loader.get_analyzer_class("dec")
    registered = loader.list_registered()
    assert registered["dec"]["loaded"] is True


def test_list_registered_metadata_preserved():
    loader = LazyAnalyzerLoader()
    loader.register("test", "os", "sep", metadata={"key": "value"})
    registered = loader.list_registered()
    assert registered["test"]["metadata"]["key"] == "value"


# ---------------------------------------------------------------------------
# __len__, __contains__, __repr__
# ---------------------------------------------------------------------------


def test_len_empty_loader():
    loader = LazyAnalyzerLoader()
    assert len(loader) == 0


def test_len_after_register():
    loader = LazyAnalyzerLoader()
    loader.register("a", "json", "JSONDecoder")
    loader.register("b", "json", "JSONEncoder")
    assert len(loader) == 2


def test_contains_returns_false_for_unknown():
    loader = LazyAnalyzerLoader()
    assert "unknown" not in loader


def test_contains_returns_true_after_register():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    assert "dec" in loader


def test_repr_shows_counts():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    loader.register("enc", "json", "JSONEncoder")
    rep = repr(loader)
    assert "LazyAnalyzerLoader" in rep
    assert "registered=2" in rep
    assert "loaded=0" in rep

    loader.get_analyzer_class("dec")
    rep = repr(loader)
    assert "loaded=1" in rep


# ---------------------------------------------------------------------------
# get_global_lazy_loader singleton
# ---------------------------------------------------------------------------


def test_get_global_lazy_loader_is_singleton():
    loader1 = get_global_lazy_loader()
    loader2 = get_global_lazy_loader()
    assert loader1 is loader2


def test_get_global_lazy_loader_returns_lazy_analyzer_loader():
    loader = get_global_lazy_loader()
    assert isinstance(loader, LazyAnalyzerLoader)


# ---------------------------------------------------------------------------
# thread safety
# ---------------------------------------------------------------------------


def test_thread_safe_concurrent_get_analyzer_class():
    loader = LazyAnalyzerLoader()
    loader.register("dec", "json", "JSONDecoder")
    results = []
    lock = threading.Lock()

    def load():
        cls = loader.get_analyzer_class("dec")
        with lock:
            results.append(cls)

    threads = [threading.Thread(target=load) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 8
    assert all(r is results[0] for r in results)
