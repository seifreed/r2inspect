from r2inspect.registry.default_registry import (
    AnalyzerCategory,
    create_default_registry,
    get_category_registry,
    get_format_specific_analyzers,
    get_minimal_registry,
)


def test_default_registry_contains_core_analyzers():
    registry = create_default_registry()
    assert "pe_analyzer" in registry
    assert "elf_analyzer" in registry
    assert "macho_analyzer" in registry


def test_get_format_specific_analyzers_filters():
    pe_registry = get_format_specific_analyzers("PE")
    assert "pe_analyzer" in pe_registry
    assert "elf_analyzer" not in pe_registry


def test_filtered_registry_resolves_real_analyzer_class():
    # A filtered registry must still resolve to the real analyzer class. The
    # filter previously copied metadata.analyzer_class, which under lazy loading
    # is a LazyPlaceholder, so get_analyzer_class returned the placeholder.
    pe_registry = get_format_specific_analyzers("PE")
    cls = pe_registry.get_analyzer_class("pe_analyzer")
    assert cls is not None
    assert cls.__name__ == "PEAnalyzer"
    assert "Placeholder" not in cls.__name__


def test_get_minimal_registry_only_required():
    minimal = get_minimal_registry()
    assert all(info["required"] for info in minimal.list_analyzers())


def test_get_category_registry_hashing():
    hashing = get_category_registry(AnalyzerCategory.HASHING)
    assert "ssdeep" in hashing
    for info in hashing.list_analyzers():
        assert info["category"] == AnalyzerCategory.HASHING.value
