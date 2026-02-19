from __future__ import annotations

from r2inspect.registry.analyzer_registry import AnalyzerCategory, AnalyzerRegistry
from r2inspect.registry.default_registry import (
    create_default_registry,
    get_category_registry,
    get_format_specific_analyzers,
    get_minimal_registry,
)


class _DummyAnalyzer:
    def analyze(self) -> dict:
        return {}


def test_create_default_registry_returns_registry() -> None:
    registry = create_default_registry()
    assert isinstance(registry, AnalyzerRegistry)
    assert len(list(registry)) > 0


def test_create_default_registry_has_pe_analyzer() -> None:
    registry = create_default_registry()
    assert registry.is_registered("pe_analyzer")


def test_create_default_registry_has_elf_analyzer() -> None:
    registry = create_default_registry()
    assert registry.is_registered("elf_analyzer")


def test_create_default_registry_loads_entry_points_without_error() -> None:
    registry = create_default_registry()
    assert registry is not None


def test_get_format_specific_analyzers_pe() -> None:
    registry = get_format_specific_analyzers("PE")
    assert isinstance(registry, AnalyzerRegistry)
    names = list(registry)
    assert "pe_analyzer" in names


def test_get_format_specific_analyzers_elf() -> None:
    registry = get_format_specific_analyzers("ELF")
    names = list(registry)
    assert "elf_analyzer" in names


def test_get_format_specific_analyzers_excludes_other_formats() -> None:
    registry = get_format_specific_analyzers("ELF")
    names = list(registry)
    assert "pe_analyzer" not in names


def test_get_minimal_registry_returns_only_required() -> None:
    registry = get_minimal_registry()
    assert isinstance(registry, AnalyzerRegistry)
    for name in registry:
        meta = registry.get_metadata(name)
        assert meta is not None
        assert meta.required is True


def test_get_category_registry_format_category() -> None:
    registry = get_category_registry(AnalyzerCategory.FORMAT)
    assert isinstance(registry, AnalyzerRegistry)
    names = list(registry)
    assert len(names) > 0
    for name in names:
        meta = registry.get_metadata(name)
        assert meta.category == AnalyzerCategory.FORMAT


def test_get_category_registry_hashing_category() -> None:
    registry = get_category_registry(AnalyzerCategory.HASHING)
    names = list(registry)
    assert "ssdeep" in names or "tlsh" in names or len(names) > 0


def test_get_category_registry_detection_category() -> None:
    registry = get_category_registry(AnalyzerCategory.DETECTION)
    names = list(registry)
    assert len(names) > 0


def test_filter_registry_uses_metadata_predicate() -> None:
    full = create_default_registry()
    filtered = get_format_specific_analyzers("MACH0")
    full_count = len(list(full))
    filtered_count = len(list(filtered))
    assert filtered_count <= full_count


def test_analyzer_registry_get_base_analyzer_class() -> None:
    registry = AnalyzerRegistry()
    registry._base_analyzer_class = None
    base = registry._get_base_analyzer_class()
    assert base is not None


def test_analyzer_registry_is_base_analyzer_returns_false_for_non_base() -> None:
    registry = AnalyzerRegistry()
    result = registry.is_base_analyzer(_DummyAnalyzer)
    assert result is False


def test_analyzer_registry_is_base_analyzer_not_a_class() -> None:
    registry = AnalyzerRegistry()
    result = registry.is_base_analyzer("not_a_class")  # type: ignore
    assert result is False


def test_analyzer_registry_extract_metadata_from_class_raises_for_non_base() -> None:
    import pytest
    registry = AnalyzerRegistry()
    with pytest.raises(Exception):
        registry.extract_metadata_from_class(_DummyAnalyzer)


def test_analyzer_registry_validate_analyzer_valid_class() -> None:
    registry = AnalyzerRegistry()
    is_valid, error = registry.validate_analyzer(_DummyAnalyzer)
    assert is_valid is True
    assert error is None


def test_analyzer_registry_validate_analyzer_not_a_class() -> None:
    registry = AnalyzerRegistry()
    is_valid, error = registry.validate_analyzer("string")  # type: ignore
    assert is_valid is False
    assert error is not None


def test_analyzer_registry_register_from_instance_non_base_raises() -> None:
    import pytest
    registry = AnalyzerRegistry()
    instance = _DummyAnalyzer()
    with pytest.raises(ValueError, match="not a BaseAnalyzer subclass"):
        registry.register_from_instance(instance)
