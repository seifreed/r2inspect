from __future__ import annotations

import pytest

from r2inspect.registry.categories import AnalyzerCategory
from r2inspect.registry.metadata import AnalyzerMetadata


class TestAnalyzer:
    """Test analyzer class"""
    pass


class AnotherAnalyzer:
    """Another test analyzer"""
    pass


def test_metadata_empty_name_raises():
    """Test that empty name raises ValueError"""
    with pytest.raises(ValueError, match="Analyzer name cannot be empty"):
        AnalyzerMetadata("", TestAnalyzer, AnalyzerCategory.FORMAT)


def test_metadata_none_class_raises():
    """Test that None analyzer_class raises ValueError"""
    with pytest.raises(ValueError, match="Analyzer class cannot be None"):
        AnalyzerMetadata("test", None, AnalyzerCategory.FORMAT)  # type: ignore[arg-type]


def test_metadata_invalid_category_raises():
    """Test that invalid category raises TypeError"""
    with pytest.raises(TypeError, match="Category must be AnalyzerCategory"):
        AnalyzerMetadata("test", TestAnalyzer, "invalid")  # type: ignore[arg-type]


def test_metadata_supports_format_with_empty_formats():
    """Test supports_format returns True when file_formats is empty"""
    meta = AnalyzerMetadata(
        name="test",
        analyzer_class=TestAnalyzer,
        category=AnalyzerCategory.FORMAT,
    )
    assert meta.file_formats == set()
    assert meta.supports_format("PE") is True
    assert meta.supports_format("ELF") is True
    assert meta.supports_format("MACHO") is True


def test_metadata_supports_format_with_specific_formats():
    """Test supports_format returns correct value for specific formats"""
    meta = AnalyzerMetadata(
        name="test",
        analyzer_class=TestAnalyzer,
        category=AnalyzerCategory.FORMAT,
        file_formats={"PE", "ELF"},
    )
    assert meta.supports_format("PE") is True
    assert meta.supports_format("pe") is True
    assert meta.supports_format("ELF") is True
    assert meta.supports_format("elf") is True
    assert meta.supports_format("MACHO") is False


def test_metadata_supports_format_case_insensitive():
    """Test supports_format is case insensitive"""
    meta = AnalyzerMetadata(
        name="test",
        analyzer_class=TestAnalyzer,
        category=AnalyzerCategory.FORMAT,
        file_formats={"Pe", "Elf"},
    )
    assert meta.supports_format("PE") is True
    assert meta.supports_format("pe") is True
    assert meta.supports_format("ELF") is True
    assert meta.supports_format("eLf") is True


def test_metadata_to_dict():
    """Test to_dict returns correct dictionary structure"""
    meta = AnalyzerMetadata(
        name="test_analyzer",
        analyzer_class=TestAnalyzer,
        category=AnalyzerCategory.HASHING,
        file_formats={"PE", "ELF"},
        required=True,
        dependencies={"dep1", "dep2"},
        description="Test description",
    )
    result = meta.to_dict()
    
    assert result["name"] == "test_analyzer"
    assert result["class"] == "TestAnalyzer"
    assert "TestAnalyzer" in result["module"] or result["module"] == "test_metadata_registry"
    assert result["category"] == "hashing"
    assert set(result["file_formats"]) == {"PE", "ELF"}
    assert result["required"] is True
    assert set(result["dependencies"]) == {"dep1", "dep2"}
    assert result["description"] == "Test description"


def test_metadata_to_dict_with_defaults():
    """Test to_dict with default values"""
    meta = AnalyzerMetadata(
        name="simple",
        analyzer_class=TestAnalyzer,
        category=AnalyzerCategory.METADATA,
    )
    result = meta.to_dict()
    
    assert result["name"] == "simple"
    assert result["class"] == "TestAnalyzer"
    assert result["category"] == "metadata"
    assert result["file_formats"] == []
    assert result["required"] is False
    assert result["dependencies"] == []
    assert result["description"] == ""


def test_metadata_post_init_sets_defaults():
    """Test __post_init__ sets None values to empty sets"""
    meta = AnalyzerMetadata(
        name="test",
        analyzer_class=TestAnalyzer,
        category=AnalyzerCategory.DETECTION,
        file_formats=None,
        dependencies=None,
    )
    assert meta.file_formats == set()
    assert meta.dependencies == set()


def test_metadata_all_categories():
    """Test metadata creation with all category types"""
    categories = [
        AnalyzerCategory.FORMAT,
        AnalyzerCategory.HASHING,
        AnalyzerCategory.DETECTION,
        AnalyzerCategory.METADATA,
        AnalyzerCategory.SECURITY,
        AnalyzerCategory.SIMILARITY,
        AnalyzerCategory.BEHAVIORAL,
    ]
    
    for category in categories:
        meta = AnalyzerMetadata(
            name=f"test_{category.value}",
            analyzer_class=TestAnalyzer,
            category=category,
        )
        assert meta.category == category
        assert meta.to_dict()["category"] == category.value


def test_metadata_required_flag():
    """Test required flag handling"""
    meta_required = AnalyzerMetadata(
        name="required_analyzer",
        analyzer_class=TestAnalyzer,
        category=AnalyzerCategory.FORMAT,
        required=True,
    )
    assert meta_required.required is True
    
    meta_optional = AnalyzerMetadata(
        name="optional_analyzer",
        analyzer_class=TestAnalyzer,
        category=AnalyzerCategory.FORMAT,
        required=False,
    )
    assert meta_optional.required is False


def test_metadata_dependencies():
    """Test dependencies handling"""
    meta = AnalyzerMetadata(
        name="dependent",
        analyzer_class=TestAnalyzer,
        category=AnalyzerCategory.FORMAT,
        dependencies={"dep1", "dep2", "dep3"},
    )
    assert meta.dependencies == {"dep1", "dep2", "dep3"}
    result = meta.to_dict()
    assert set(result["dependencies"]) == {"dep1", "dep2", "dep3"}
