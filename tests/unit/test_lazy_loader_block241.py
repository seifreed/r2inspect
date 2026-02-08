import importlib

import pytest

from r2inspect.lazy_loader import LazyAnalyzerLoader, get_global_lazy_loader
from r2inspect.lazy_loader_stats import build_stats, print_stats


def test_lazy_loader_register_load_and_stats(capsys):
    loader = LazyAnalyzerLoader()
    loader.register(
        name="base",
        module_path="r2inspect.schemas.base",
        class_name="AnalysisResultBase",
        category="schemas",
        formats={"PE"},
        metadata={"k": "v"},
    )

    assert loader.is_registered("base") is True
    assert loader.is_loaded("base") is False
    assert "base" in loader
    assert len(loader) == 1

    analyzer_class = loader.get_analyzer_class("base")
    assert analyzer_class.__name__ == "AnalysisResultBase"
    assert loader.is_loaded("base") is True

    assert loader.get_analyzer_class("base") is analyzer_class

    stats = loader.get_stats()
    assert stats["registered"] == 1
    assert stats["loaded"] == 1
    assert stats["cache_hits"] >= 1

    listed = loader.list_registered()
    assert listed["base"]["module_path"] == "r2inspect.schemas.base"
    assert listed["base"]["loaded"] is True

    loader.unload("base")
    assert loader.is_loaded("base") is False

    preload_results = loader.preload("base")
    assert preload_results["base"] is True

    preload_cat = loader.preload_category("schemas")
    assert preload_cat["base"] is True

    cleared = loader.clear_cache()
    assert cleared >= 1

    assert loader.unregister("base") is True
    assert loader.unregister("missing") is False

    print_stats(loader)
    captured = capsys.readouterr()
    assert "Lazy Loader Statistics" in captured.out

    stats2 = build_stats(loader)
    assert "cache_hit_rate" in stats2


def test_lazy_loader_errors():
    loader = LazyAnalyzerLoader()

    with pytest.raises(ValueError):
        loader.register(name="", module_path="x", class_name="Y")

    with pytest.raises(ValueError):
        loader.register(name="x", module_path="", class_name="Y")

    loader.register(name="badmod", module_path="r2inspect.missing", class_name="Nope")
    with pytest.raises(ImportError):
        loader.get_analyzer_class("badmod")

    loader.register(name="badcls", module_path="r2inspect.schemas.base", class_name="Missing")
    with pytest.raises(AttributeError):
        loader.get_analyzer_class("badcls")

    assert loader.get_analyzer_class("unknown") is None


def test_global_lazy_loader_singleton():
    loader1 = get_global_lazy_loader()
    loader2 = get_global_lazy_loader()
    assert loader1 is loader2


def test_register_overwrite_warning_and_unregister_cached_item():
    loader = LazyAnalyzerLoader()
    loader.register(name="dup", module_path="json", class_name="JSONDecoder")
    # Different target triggers overwrite warning branch
    loader.register(name="dup", module_path="json", class_name="JSONEncoder")
    cls = loader.get_analyzer_class("dup")
    assert cls is not None
    assert loader.is_loaded("dup") is True
    assert loader.unregister("dup") is True
    assert loader.is_registered("dup") is False
