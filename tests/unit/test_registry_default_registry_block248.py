from r2inspect.registry.analyzer_registry import AnalyzerCategory
from r2inspect.registry.default_registry import (
    create_default_registry,
    get_category_registry,
    get_format_specific_analyzers,
    get_minimal_registry,
)


def test_default_registry_and_filters():
    registry = create_default_registry()
    assert len(registry) > 0
    assert registry.is_registered("pe_analyzer") is True

    minimal = get_minimal_registry()
    assert minimal.is_registered("pe_analyzer") is True
    assert minimal.is_registered("ssdeep") is False

    pe_only = get_format_specific_analyzers("PE")
    assert pe_only.is_registered("pe_analyzer") is True

    hashing = get_category_registry(AnalyzerCategory.HASHING)
    assert hashing.is_registered("ssdeep") is True
