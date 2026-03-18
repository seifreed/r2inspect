"""Comprehensive tests for lazy_loader.py - 100% coverage target.

No unittest.mock usage; all tests use real objects.
"""

from r2inspect.lazy_loader import (
    LazyAnalyzerLoader,
    LazyAnalyzerSpec,
    _init_loader_stats,
    get_global_lazy_loader,
)


def test_lazy_loader_init():
    """Test LazyLoader initialization."""
    loader = LazyAnalyzerLoader()
    assert len(loader) == 0
    assert repr(loader) is not None


def test_lazy_loader_basic_functionality():
    """Test basic functionality of lazy_loader."""
    loader = LazyAnalyzerLoader()
    loader.register("os_path", "os.path", "exists")
    assert loader.is_registered("os_path") is True
    cls = loader.get_analyzer_class("os_path")
    assert cls is not None
    assert loader.is_loaded("os_path") is True


def test_lazy_loader_error_handling():
    """Test error handling in lazy_loader."""
    loader = LazyAnalyzerLoader()
    loader.register("bad", "nonexistent.module.xyz", "BadClass")
    try:
        loader.get_analyzer_class("bad")
    except ImportError:
        pass
    assert loader._stats["failed_loads"] == 1


def test_lazy_loader_edge_cases():
    """Test edge cases in lazy_loader."""
    loader = LazyAnalyzerLoader()
    # Getting unregistered returns None
    assert loader.get_analyzer_class("nope") is None
    # Unload unregistered returns False
    assert loader.unload("nope") is False
    # Unregister unregistered returns False
    assert loader.unregister("nope") is False


def test_lazy_loader_integration():
    """Test integration scenarios for lazy_loader."""
    spec = LazyAnalyzerSpec(
        module_path="os.path",
        class_name="join",
        category="utils",
        formats={"all"},
        metadata={"test": True},
    )
    assert spec.module_path == "os.path"
    assert spec.class_name == "join"

    stats = _init_loader_stats()
    assert stats["load_count"] == 0

    global_loader = get_global_lazy_loader()
    assert global_loader is not None
