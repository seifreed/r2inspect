from __future__ import annotations

import sys

import pytest

from r2inspect import __main__ as r2_main
from r2inspect.lazy_loader import LazyAnalyzerLoader, get_global_lazy_loader
from r2inspect.lazy_loader_stats import build_stats, print_stats


def test_lazy_loader_full_cycle() -> None:
    loader = LazyAnalyzerLoader()

    with pytest.raises(ValueError):
        loader.register("", "r2inspect.modules.pe_analyzer", "PEAnalyzer")

    with pytest.raises(ValueError):
        loader.register("pe", "", "PEAnalyzer")

    loader.register(
        "pe",
        "r2inspect.modules.pe_analyzer",
        "PEAnalyzer",
        category="format",
        formats={"PE"},
        metadata={"k": "v"},
    )
    loader.register("dup", "r2inspect.modules.pe_analyzer", "PEAnalyzer")
    loader.register("dup", "r2inspect.modules.elf_analyzer", "ELFAnalyzer")
    loader.register(
        "pe",
        "r2inspect.modules.pe_analyzer",
        "PEAnalyzer",
        category="format",
    )

    assert loader.is_registered("pe") is True
    assert loader.is_loaded("pe") is False
    assert loader.get_analyzer_class("missing") is None

    pe_class = loader.get_analyzer_class("pe")
    assert pe_class is not None
    assert loader.is_loaded("pe") is True
    assert loader.get_analyzer_class("pe") is pe_class

    stats = loader.get_stats()
    assert stats["registered"] >= 1
    assert stats["loaded"] >= 1

    assert loader.unload("pe") is True
    assert loader.unload("pe") is False
    assert loader.is_loaded("pe") is False

    assert "pe" in loader
    assert len(loader) == 2
    assert "LazyAnalyzerLoader" in repr(loader)

    preload_result = loader.preload("pe", "missing")
    assert preload_result["pe"] is True
    assert preload_result["missing"] is True

    loader.register("badpreload", "r2inspect.missing_module", "Nope")
    preload_fail = loader.preload("badpreload")
    assert preload_fail["badpreload"] is False

    loader.register("elf", "r2inspect.modules.elf_analyzer", "ELFAnalyzer", category="format")
    category_result = loader.preload_category("format")
    assert category_result["pe"] is True
    assert category_result["elf"] is True

    registered = loader.list_registered()
    assert "pe" in registered
    assert registered["pe"]["module_path"] == "r2inspect.modules.pe_analyzer"

    assert loader.unregister("pe") is True
    assert loader.unregister("pe") is False

    assert loader.clear_cache() >= 0


def test_lazy_loader_stats_helpers() -> None:
    loader = LazyAnalyzerLoader()
    loader.register("pe", "r2inspect.modules.pe_analyzer", "PEAnalyzer")
    loader.get_analyzer_class("pe")

    stats = build_stats(loader)
    assert stats["registered"] == 1
    assert stats["loaded"] == 1
    assert stats["unloaded"] == 0

    print_stats(loader)


def test_lazy_loader_error_paths() -> None:
    loader = LazyAnalyzerLoader()
    loader.register("badmod", "r2inspect.missing_module", "Nope")
    with pytest.raises(ImportError):
        loader.get_analyzer_class("badmod")

    loader.register("badcls", "r2inspect.modules.pe_analyzer", "Nope")
    with pytest.raises(AttributeError):
        loader.get_analyzer_class("badcls")


def test_global_lazy_loader_singleton() -> None:
    global_loader = get_global_lazy_loader()
    assert global_loader is get_global_lazy_loader()


def test_main_entrypoint_returns_status() -> None:
    argv = sys.argv[:]
    try:
        sys.argv = ["r2inspect", "--version"]
        assert r2_main.main() == 0
    finally:
        sys.argv = argv
