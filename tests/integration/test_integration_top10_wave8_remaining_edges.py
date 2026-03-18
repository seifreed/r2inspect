"""Remaining edge coverage for wave8 top10 modules."""

from __future__ import annotations

import pytest

from r2inspect.registry.categories import AnalyzerCategory
from r2inspect.registry.metadata_extraction import (
    auto_extract_metadata,
    extract_metadata_from_class,
    parse_category,
)


class _FakeAnalyzer:
    def __init__(self, adapter=None, config=None, filepath=None):
        _ = adapter, config, filepath
        self._name = "fake"

    def get_name(self) -> str:
        return self._name

    def get_category(self) -> str:
        return "metadata"

    def get_supported_formats(self) -> set[str]:
        return {"PE", "ELF"}

    def get_description(self) -> str:
        return "fake analyzer"


class _BadInitAnalyzer:
    def __init__(self, adapter=None, config=None, filepath=None):
        _ = adapter, config, filepath
        raise RuntimeError("boom")


def test_parse_category_paths() -> None:
    assert parse_category(AnalyzerCategory.METADATA) == AnalyzerCategory.METADATA
    assert parse_category("metadata") == AnalyzerCategory.METADATA
    with pytest.raises(ValueError):
        parse_category("unknown")
    with pytest.raises(TypeError):
        parse_category(123)


def test_extract_metadata_from_class_paths() -> None:
    def is_base(cls):
        return cls is _FakeAnalyzer

    metadata = extract_metadata_from_class(_FakeAnalyzer, is_base_analyzer=is_base, name="renamed")
    assert metadata["name"] == "renamed"
    assert metadata["category"] == "metadata"
    assert metadata["formats"] == {"PE", "ELF"}
    assert metadata["description"] == "fake analyzer"

    with pytest.raises(ValueError):
        extract_metadata_from_class(_BadInitAnalyzer, is_base_analyzer=lambda _c: False)

    with pytest.raises(RuntimeError):
        extract_metadata_from_class(_BadInitAnalyzer, is_base_analyzer=lambda _c: True)


def test_auto_extract_metadata_paths() -> None:
    # No auto extract path
    out = auto_extract_metadata(
        _FakeAnalyzer,
        name="x",
        category=None,
        file_formats=None,
        description="",
        auto_extract=False,
        is_base_analyzer=lambda _c: True,
    )
    assert out == (None, None, "")

    # Successful auto-extract path
    out = auto_extract_metadata(
        _FakeAnalyzer,
        name="x",
        category=None,
        file_formats=None,
        description="",
        auto_extract=True,
        is_base_analyzer=lambda _c: True,
    )
    assert out[0] == AnalyzerCategory.METADATA
    assert out[1] == {"PE", "ELF"}
    assert out[2] == "fake analyzer"

    # Fallback on extraction failure path
    out = auto_extract_metadata(
        _BadInitAnalyzer,
        name="x",
        category=AnalyzerCategory.SECURITY,
        file_formats={"PE"},
        description="desc",
        auto_extract=True,
        is_base_analyzer=lambda _c: True,
    )
    assert out == (AnalyzerCategory.SECURITY, {"PE"}, "desc")
