from __future__ import annotations

import os

import pytest

from r2inspect.registry.analyzer_registry import AnalyzerCategory, AnalyzerRegistry


class DummyAnalyzer:
    """Dummy analyzer for testing"""
    
    def __init__(self, adapter: object = None) -> None:
        self.adapter = adapter
    
    def analyze(self) -> dict:
        return {}


def test_registry_initialization_default_lazy_loading() -> None:
    """Test registry initialization with default lazy loading"""
    registry = AnalyzerRegistry()
    assert registry._lazy_loading is True


def test_registry_initialization_lazy_loading_enabled() -> None:
    """Test registry initialization with lazy_loading=True"""
    registry = AnalyzerRegistry(lazy_loading=True)
    assert registry._lazy_loading is True
    assert registry._lazy_loader is not None


def test_registry_initialization_lazy_loading_disabled() -> None:
    """Test registry initialization with lazy_loading=False"""
    registry = AnalyzerRegistry(lazy_loading=False)
    assert registry._lazy_loading is False
    assert registry._lazy_loader is None


def test_registry_initialization_env_var_0() -> None:
    """Test registry initialization with R2INSPECT_LAZY_LOADING=0"""
    os.environ["R2INSPECT_LAZY_LOADING"] = "0"
    try:
        registry = AnalyzerRegistry()
        assert registry._lazy_loading is False
    finally:
        del os.environ["R2INSPECT_LAZY_LOADING"]


def test_registry_initialization_env_var_false() -> None:
    """Test registry initialization with R2INSPECT_LAZY_LOADING=false"""
    os.environ["R2INSPECT_LAZY_LOADING"] = "false"
    try:
        registry = AnalyzerRegistry()
        assert registry._lazy_loading is False
    finally:
        del os.environ["R2INSPECT_LAZY_LOADING"]


def test_registry_initialization_env_var_no() -> None:
    """Test registry initialization with R2INSPECT_LAZY_LOADING=no"""
    os.environ["R2INSPECT_LAZY_LOADING"] = "no"
    try:
        registry = AnalyzerRegistry()
        assert registry._lazy_loading is False
    finally:
        del os.environ["R2INSPECT_LAZY_LOADING"]


def test_registry_initialization_env_var_off() -> None:
    """Test registry initialization with R2INSPECT_LAZY_LOADING=off"""
    os.environ["R2INSPECT_LAZY_LOADING"] = "off"
    try:
        registry = AnalyzerRegistry()
        assert registry._lazy_loading is False
    finally:
        del os.environ["R2INSPECT_LAZY_LOADING"]


def test_is_base_analyzer_not_class() -> None:
    """Test is_base_analyzer with non-class"""
    registry = AnalyzerRegistry()
    
    result = registry.is_base_analyzer("not_a_class")  # type: ignore
    assert result is False


def test_is_base_analyzer_no_base_analyzer() -> None:
    """Test is_base_analyzer when BaseAnalyzer not available"""
    registry = AnalyzerRegistry()
    registry._base_analyzer_class = None
    
    # Force _get_base_analyzer_class to return None
    with pytest.MonkeyPatch.context() as m:
        def mock_get_base() -> None:
            return None
        
        registry._get_base_analyzer_class = mock_get_base  # type: ignore
        result = registry.is_base_analyzer(DummyAnalyzer)
        assert result is False


def test_validate_analyzer_not_class() -> None:
    """Test validate_analyzer with non-class"""
    registry = AnalyzerRegistry()
    
    is_valid, error = registry.validate_analyzer("not_a_class")  # type: ignore
    assert is_valid is False
    assert "must be a class" in error


def test_validate_analyzer_no_analyze_method() -> None:
    """Test validate_analyzer when analyze method missing"""
    class NoAnalyzeAnalyzer:
        def __init__(self) -> None:
            pass
    
    registry = AnalyzerRegistry()
    
    # Make it think it's a BaseAnalyzer
    with pytest.MonkeyPatch.context() as m:
        m.setattr(registry, "is_base_analyzer", lambda x: True)
        
        is_valid, error = registry.validate_analyzer(NoAnalyzeAnalyzer)
        assert is_valid is False
        assert "must implement analyze()" in error


def test_validate_analyzer_analyze_still_abstract() -> None:
    """Test validate_analyzer when analyze is still abstract"""
    class AbstractAnalyzer:
        def analyze(self) -> dict:
            pass
    
    # Mark analyze as abstract
    AbstractAnalyzer.analyze.__isabstractmethod__ = True  # type: ignore
    
    registry = AnalyzerRegistry()
    
    with pytest.MonkeyPatch.context() as m:
        m.setattr(registry, "is_base_analyzer", lambda x: True)
        
        is_valid, error = registry.validate_analyzer(AbstractAnalyzer)
        assert is_valid is False
        assert "still abstract" in error


def test_validate_analyzer_no_init() -> None:
    """Test validate_analyzer when __init__ is inherited"""
    # All Python classes have __init__, even if inherited
    # So this test verifies that having __init__ is valid
    class ValidAnalyzer:
        def analyze(self) -> dict:
            return {}
    
    registry = AnalyzerRegistry()
    
    is_valid, error = registry.validate_analyzer(ValidAnalyzer)
    # Should be valid because __init__ is inherited from object
    assert is_valid is True
    assert error is None


def test_validate_analyzer_success() -> None:
    """Test validate_analyzer with valid analyzer"""
    registry = AnalyzerRegistry()
    
    is_valid, error = registry.validate_analyzer(DummyAnalyzer)
    assert is_valid is True
    assert error is None


def test_register_empty_name() -> None:
    """Test register with empty name"""
    registry = AnalyzerRegistry()
    
    with pytest.raises(ValueError, match="name cannot be empty"):
        registry.register(
            name="",
            analyzer_class=DummyAnalyzer,
            category=AnalyzerCategory.HASHING,
        )


def test_register_neither_class_nor_lazy() -> None:
    """Test register with neither analyzer_class nor lazy params"""
    registry = AnalyzerRegistry()
    
    with pytest.raises(ValueError, match="Must provide either"):
        registry.register(
            name="test",
            category=AnalyzerCategory.HASHING,
        )


def test_register_both_class_and_lazy() -> None:
    """Test register with both analyzer_class and lazy params"""
    registry = AnalyzerRegistry()
    
    with pytest.raises(ValueError, match="Cannot provide both"):
        registry.register(
            name="test",
            analyzer_class=DummyAnalyzer,
            module_path="test.module",
            class_name="TestClass",
            category=AnalyzerCategory.HASHING,
        )


def test_register_lazy_without_category() -> None:
    """Test lazy register without category"""
    registry = AnalyzerRegistry(lazy_loading=True)
    
    with pytest.raises(ValueError, match="Category is required"):
        registry.register(
            name="test",
            module_path="test.module",
            class_name="TestClass",
        )


def test_register_lazy_success() -> None:
    """Test successful lazy registration"""
    registry = AnalyzerRegistry(lazy_loading=True)
    
    registry.register(
        name="test_lazy",
        module_path="test.module",
        class_name="TestClass",
        category=AnalyzerCategory.HASHING,
        file_formats={"PE"},
        required=True,
        description="Test lazy analyzer",
    )
    
    assert registry.is_registered("test_lazy")


def test_register_lazy_with_string_category() -> None:
    """Test lazy registration with string category"""
    registry = AnalyzerRegistry(lazy_loading=True)
    
    registry.register(
        name="test_lazy",
        module_path="test.module",
        class_name="TestClass",
        category="hashing",
        file_formats={"PE"},
    )
    
    assert registry.is_registered("test_lazy")


def test_register_eager_without_category() -> None:
    """Test eager register without category raises error"""
    registry = AnalyzerRegistry(lazy_loading=False)
    
    with pytest.raises(ValueError, match="Category must be provided"):
        registry.register(
            name="test",
            analyzer_class=DummyAnalyzer,
        )


def test_register_eager_success() -> None:
    """Test successful eager registration"""
    registry = AnalyzerRegistry(lazy_loading=False)
    
    registry.register(
        name="test_eager",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.HASHING,
        file_formats={"PE"},
        required=False,
        description="Test eager analyzer",
    )
    
    assert registry.is_registered("test_eager")


def test_register_with_dependencies() -> None:
    """Test registration with dependencies"""
    registry = AnalyzerRegistry(lazy_loading=False)
    
    registry.register(
        name="dependent",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.HASHING,
        dependencies={"base_analyzer", "other_analyzer"},
    )
    
    assert registry.is_registered("dependent")


def test_unregister_existing() -> None:
    """Test unregister existing analyzer"""
    registry = AnalyzerRegistry(lazy_loading=False)
    
    registry.register(
        name="to_remove",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.HASHING,
    )
    
    result = registry.unregister("to_remove")
    assert result is True
    assert not registry.is_registered("to_remove")


def test_unregister_non_existing() -> None:
    """Test unregister non-existing analyzer"""
    registry = AnalyzerRegistry()
    
    result = registry.unregister("non_existing")
    assert result is False


def test_is_registered_true() -> None:
    """Test is_registered returns True for registered analyzer"""
    registry = AnalyzerRegistry(lazy_loading=False)
    
    registry.register(
        name="test",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.HASHING,
    )
    
    assert registry.is_registered("test") is True


def test_is_registered_false() -> None:
    """Test is_registered returns False for non-registered analyzer"""
    registry = AnalyzerRegistry()
    
    assert registry.is_registered("non_existing") is False


def test_load_entry_points() -> None:
    """Test load_entry_points"""
    registry = AnalyzerRegistry()
    
    # Should not raise even with no entry points
    count = registry.load_entry_points("r2inspect.analyzers")
    assert count >= 0


def test_register_from_instance_not_base_analyzer() -> None:
    """Test register_from_instance with non-BaseAnalyzer instance"""
    registry = AnalyzerRegistry()
    
    instance = DummyAnalyzer()
    
    with pytest.raises(ValueError, match="not a BaseAnalyzer subclass"):
        registry.register_from_instance(instance)


def test_parse_category_invalid_string() -> None:
    """Test _parse_category with invalid string"""
    registry = AnalyzerRegistry()
    
    with pytest.raises((ValueError, KeyError)):
        registry._parse_category("invalid_category")


def test_parse_category_valid_string() -> None:
    """Test _parse_category with valid string"""
    registry = AnalyzerRegistry()
    
    result = registry._parse_category("hashing")
    assert result == AnalyzerCategory.HASHING


def test_parse_category_enum() -> None:
    """Test _parse_category with AnalyzerCategory enum"""
    registry = AnalyzerRegistry()
    
    result = registry._parse_category(AnalyzerCategory.HASHING)
    assert result == AnalyzerCategory.HASHING


def test_lazy_fallback_analyzer_class() -> None:
    """Test _lazy_fallback_analyzer_class imports module"""
    registry = AnalyzerRegistry(lazy_loading=False)
    
    # Test with a real module
    analyzer_class = registry._lazy_fallback_analyzer_class(
        "r2inspect.modules.resource_analyzer",
        "ResourceAnalyzer"
    )
    
    assert analyzer_class is not None
    assert analyzer_class.__name__ == "ResourceAnalyzer"


def test_lazy_fallback_analyzer_class_none_params() -> None:
    """Test _lazy_fallback_analyzer_class with None params"""
    registry = AnalyzerRegistry()
    
    with pytest.raises(ValueError, match="module_path and class_name are required"):
        registry._lazy_fallback_analyzer_class(None, None)


def test_ensure_analyzer_class_none() -> None:
    """Test _ensure_analyzer_class with None"""
    registry = AnalyzerRegistry()
    
    with pytest.raises(ValueError, match="analyzer_class is required"):
        registry._ensure_analyzer_class(None)


def test_ensure_analyzer_class_valid() -> None:
    """Test _ensure_analyzer_class with valid class"""
    registry = AnalyzerRegistry()
    
    result = registry._ensure_analyzer_class(DummyAnalyzer)
    assert result == DummyAnalyzer


def test_ensure_category_none() -> None:
    """Test _ensure_category with None category"""
    registry = AnalyzerRegistry()
    
    with pytest.raises(ValueError, match="Category must be provided"):
        registry._ensure_category(DummyAnalyzer, None)


def test_ensure_category_string() -> None:
    """Test _ensure_category with string category"""
    registry = AnalyzerRegistry()
    
    result = registry._ensure_category(DummyAnalyzer, "hashing")
    assert result == AnalyzerCategory.HASHING


def test_ensure_category_enum() -> None:
    """Test _ensure_category with AnalyzerCategory enum"""
    registry = AnalyzerRegistry()
    
    result = registry._ensure_category(DummyAnalyzer, AnalyzerCategory.HASHING)
    assert result == AnalyzerCategory.HASHING
