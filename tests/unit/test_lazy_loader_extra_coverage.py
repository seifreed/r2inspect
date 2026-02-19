#!/usr/bin/env python3
"""Extra coverage tests for lazy_loader module."""

import threading
import pytest
from unittest.mock import MagicMock, patch

from r2inspect.lazy_loader import (
    LazyAnalyzerLoader,
    LazyAnalyzerSpec,
    get_global_lazy_loader,
    _init_loader_stats,
)


def test_lazy_analyzer_spec_creation():
    """Test LazyAnalyzerSpec dataclass creation"""
    spec = LazyAnalyzerSpec(
        module_path="r2inspect.modules.pe_analyzer",
        class_name="PEAnalyzer",
        category="format",
        formats={"PE", "PE32"},
        metadata={"description": "PE analysis"}
    )
    assert spec.module_path == "r2inspect.modules.pe_analyzer"
    assert spec.class_name == "PEAnalyzer"
    assert spec.category == "format"
    assert "PE" in spec.formats
    assert spec.metadata["description"] == "PE analysis"


def test_lazy_analyzer_spec_defaults():
    """Test LazyAnalyzerSpec with default values"""
    spec = LazyAnalyzerSpec(
        module_path="test.module",
        class_name="TestClass"
    )
    assert spec.category is None
    assert spec.formats == set()
    assert spec.metadata == {}


def test_init_loader_stats():
    """Test loader stats initialization"""
    stats = _init_loader_stats()
    assert stats["load_count"] == 0
    assert stats["cache_hits"] == 0
    assert stats["cache_misses"] == 0
    assert stats["failed_loads"] == 0
    assert stats["load_times"] == {}


def test_register_empty_name_error():
    """Test that registering with empty name raises ValueError"""
    loader = LazyAnalyzerLoader()
    with pytest.raises(ValueError, match="Analyzer name cannot be empty"):
        loader.register("", "module.path", "ClassName")


def test_register_missing_module_or_class():
    """Test that missing module_path or class_name raises ValueError"""
    loader = LazyAnalyzerLoader()
    with pytest.raises(ValueError, match="Module path and class name are required"):
        loader.register("test", "", "ClassName")
    
    with pytest.raises(ValueError, match="Module path and class name are required"):
        loader.register("test", "module.path", "")


def test_register_duplicate_warning(caplog):
    """Test that duplicate registration with different path logs warning"""
    loader = LazyAnalyzerLoader()
    loader.register("test", "module.a", "ClassA")
    loader.register("test", "module.b", "ClassB")
    
    assert "already registered with different path" in caplog.text


def test_get_analyzer_class_not_found():
    """Test getting non-existent analyzer returns None"""
    loader = LazyAnalyzerLoader()
    result = loader.get_analyzer_class("nonexistent")
    assert result is None


def test_get_analyzer_class_import_error():
    """Test that ImportError is raised and tracked"""
    loader = LazyAnalyzerLoader()
    loader.register("test", "nonexistent.module", "ClassName")
    
    with pytest.raises(ImportError):
        loader.get_analyzer_class("test")
    
    assert loader._stats["failed_loads"] == 1


def test_get_analyzer_class_attribute_error():
    """Test that AttributeError is raised when class not found"""
    loader = LazyAnalyzerLoader()
    loader.register("test", "os", "NonExistentClass")
    
    with pytest.raises(AttributeError):
        loader.get_analyzer_class("test")
    
    assert loader._stats["failed_loads"] == 1


def test_get_analyzer_class_caching():
    """Test that analyzer class is cached after first load"""
    loader = LazyAnalyzerLoader()
    loader.register("os_path", "os.path", "exists")
    
    # First call - cache miss
    result1 = loader.get_analyzer_class("os_path")
    assert result1 is not None
    assert loader._stats["cache_misses"] == 1
    assert loader._stats["cache_hits"] == 0
    assert loader._stats["load_count"] == 1
    
    # Second call - cache hit
    result2 = loader.get_analyzer_class("os_path")
    assert result2 is result1
    assert loader._stats["cache_hits"] == 1


def test_is_loaded():
    """Test is_loaded method"""
    loader = LazyAnalyzerLoader()
    loader.register("os_path", "os.path", "exists")
    
    assert loader.is_loaded("os_path") is False
    loader.get_analyzer_class("os_path")
    assert loader.is_loaded("os_path") is True


def test_is_registered():
    """Test is_registered method"""
    loader = LazyAnalyzerLoader()
    assert loader.is_registered("test") is False
    
    loader.register("test", "module", "Class")
    assert loader.is_registered("test") is True


def test_unload():
    """Test unloading analyzer from cache"""
    loader = LazyAnalyzerLoader()
    loader.register("os_path", "os.path", "exists")
    
    # Not loaded yet
    assert loader.unload("os_path") is False
    
    # Load it
    loader.get_analyzer_class("os_path")
    assert loader.is_loaded("os_path") is True
    
    # Unload it
    assert loader.unload("os_path") is True
    assert loader.is_loaded("os_path") is False


def test_unregister():
    """Test unregister method"""
    loader = LazyAnalyzerLoader()
    loader.register("os_path", "os.path", "exists")
    loader.get_analyzer_class("os_path")
    
    assert loader.is_registered("os_path") is True
    assert loader.is_loaded("os_path") is True
    
    # Unregister removes both
    assert loader.unregister("os_path") is True
    assert loader.is_registered("os_path") is False
    assert loader.is_loaded("os_path") is False
    
    # Second unregister returns False
    assert loader.unregister("os_path") is False


def test_preload_success():
    """Test preloading analyzers"""
    loader = LazyAnalyzerLoader()
    loader.register("os_path", "os.path", "exists")
    loader.register("os_sep", "os", "sep")
    
    results = loader.preload("os_path", "os_sep")
    assert results["os_path"] is True
    assert results["os_sep"] is True
    assert loader.is_loaded("os_path") is True
    assert loader.is_loaded("os_sep") is True


def test_preload_failure():
    """Test preloading with failures"""
    loader = LazyAnalyzerLoader()
    loader.register("bad", "nonexistent.module", "Class")
    
    results = loader.preload("bad")
    assert results["bad"] is False


def test_preload_category():
    """Test preloading by category"""
    loader = LazyAnalyzerLoader()
    loader.register("pe", "os.path", "exists", category="format")
    loader.register("elf", "os", "sep", category="format")
    loader.register("hash", "os", "name", category="hashing")
    
    results = loader.preload_category("format")
    assert len(results) == 2
    assert results["pe"] is True
    assert results["elf"] is True
    assert "hash" not in results


def test_clear_cache():
    """Test clearing cache"""
    loader = LazyAnalyzerLoader()
    loader.register("os_path", "os.path", "exists")
    loader.register("os_sep", "os", "sep")
    
    loader.get_analyzer_class("os_path")
    loader.get_analyzer_class("os_sep")
    
    assert loader.is_loaded("os_path") is True
    assert loader.is_loaded("os_sep") is True
    
    count = loader.clear_cache()
    assert count == 2
    assert loader.is_loaded("os_path") is False
    assert loader.is_loaded("os_sep") is False


def test_list_registered():
    """Test listing registered analyzers"""
    loader = LazyAnalyzerLoader()
    loader.register("pe", "module.pe", "PEAnalyzer", category="format", formats={"PE"})
    loader.register("os_path", "os.path", "exists", category="utils")
    loader.get_analyzer_class("os_path")  # Load one that exists
    
    registered = loader.list_registered()
    assert "pe" in registered
    assert registered["pe"]["module_path"] == "module.pe"
    assert registered["pe"]["class_name"] == "PEAnalyzer"
    assert registered["pe"]["category"] == "format"
    assert "PE" in registered["pe"]["formats"]
    assert registered["pe"]["loaded"] is False
    assert registered["os_path"]["loaded"] is True


def test_len_and_contains():
    """Test __len__ and __contains__ methods"""
    loader = LazyAnalyzerLoader()
    assert len(loader) == 0
    assert "test" not in loader
    
    loader.register("test", "module", "Class")
    assert len(loader) == 1
    assert "test" in loader


def test_repr():
    """Test __repr__ method"""
    loader = LazyAnalyzerLoader()
    loader.register("test1", "module", "Class1")
    loader.register("test2", "os.path", "exists")
    
    repr_str = repr(loader)
    assert "LazyAnalyzerLoader" in repr_str
    assert "registered=2" in repr_str
    assert "loaded=0" in repr_str
    
    loader.get_analyzer_class("test2")
    repr_str = repr(loader)
    assert "loaded=1" in repr_str


def test_get_global_lazy_loader():
    """Test global loader singleton"""
    loader1 = get_global_lazy_loader()
    loader2 = get_global_lazy_loader()
    assert loader1 is loader2


def test_thread_safety():
    """Test thread-safe operations"""
    loader = LazyAnalyzerLoader()
    loader.register("os_path", "os.path", "exists")
    
    results = []
    
    def load_analyzer():
        result = loader.get_analyzer_class("os_path")
        results.append(result)
    
    threads = [threading.Thread(target=load_analyzer) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    # All threads should get the same cached instance
    assert len(results) == 10
    assert all(r is results[0] for r in results)


def test_get_stats():
    """Test get_stats method calls build_stats"""
    loader = LazyAnalyzerLoader()
    loader.register("test", "os.path", "exists")
    loader.get_analyzer_class("test")
    
    with patch('r2inspect.lazy_loader._build_stats') as mock_build:
        mock_build.return_value = {"test": "stats"}
        stats = loader.get_stats()
        assert stats == {"test": "stats"}
        mock_build.assert_called_once_with(loader)


def test_load_times_tracking():
    """Test that load times are tracked"""
    loader = LazyAnalyzerLoader()
    loader.register("os_path", "os.path", "exists")
    
    loader.get_analyzer_class("os_path")
    
    assert "os_path" in loader._stats["load_times"]
    assert loader._stats["load_times"]["os_path"] > 0


def test_metadata_preservation():
    """Test that metadata is preserved in registration"""
    loader = LazyAnalyzerLoader()
    metadata = {"author": "test", "version": "1.0"}
    loader.register("test", "os.path", "exists", metadata=metadata)
    
    registered = loader.list_registered()
    assert registered["test"]["metadata"] == metadata
