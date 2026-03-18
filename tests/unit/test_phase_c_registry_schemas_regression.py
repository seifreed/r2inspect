#!/usr/bin/env python3
"""Regression tests for registry + schemas resilience paths (Fase C)."""

from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import BaseModel

from r2inspect.registry.analyzer_registry import AnalyzerRegistry
from r2inspect.registry.categories import AnalyzerCategory
from r2inspect.registry.metadata_extraction import (
    auto_extract_metadata,
    extract_metadata_from_class,
    parse_category,
)
from r2inspect.schemas import converters
from r2inspect.schemas.hashing import HashAnalysisResult
from r2inspect.schemas.results_loader import _load_timestamp
from r2inspect.schemas.results_models import AnalysisResult


class _BaseLikeAnalyzer:
    def __init__(self, *_: object, **__: object) -> None:
        self.value = 1

    def get_name(self) -> str:
        return "base_like"

    def get_category(self) -> str:
        return "format"

    def get_supported_formats(self) -> set[str]:
        return {"PE"}

    def get_description(self) -> str:
        return "desc"


def _always_true(_cls: type) -> bool:
    return True


def test_parse_category_rejects_unknown_category_string() -> None:
    with pytest.raises(ValueError, match="Unknown category string"):
        parse_category("not-a-category")


def test_parse_category_rejects_wrong_type() -> None:
    with pytest.raises(TypeError, match="Category must be"):
        parse_category(123)


def test_extract_metadata_from_class_raises_runtime_error_on_constructor_failure() -> None:
    class _FailsInit(_BaseLikeAnalyzer):
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise RuntimeError("init failed")

    with pytest.raises(RuntimeError, match="Failed to extract metadata"):
        extract_metadata_from_class(_FailsInit, is_base_analyzer=_always_true)


def test_auto_extract_metadata_fallback_to_declared_metadata_on_failure() -> None:
    category, file_formats, description = auto_extract_metadata(
        analyzer_class=_BaseLikeAnalyzer,
        name="fallback",
        category=AnalyzerCategory.METADATA,
        file_formats={"ELF"},
        description="declared",
        auto_extract=True,
        is_base_analyzer=lambda _: False,  # triggers no auto-extract path
    )

    assert category == AnalyzerCategory.METADATA
    assert file_formats == {"ELF"}
    assert description == "declared"


def test_auto_extract_metadata_replaces_category_only_when_none() -> None:
    category, file_formats, description = auto_extract_metadata(
        analyzer_class=_BaseLikeAnalyzer,
        name="replace_category",
        category=None,
        file_formats={"ELF"},
        description="declared",
        auto_extract=True,
        is_base_analyzer=lambda _: True,
    )

    assert category == AnalyzerCategory.FORMAT
    assert file_formats == {"ELF"}
    assert description == "declared"


def test_registry_queries_missing_graph_node_raises_key_error() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    registry._analyzers = {}

    with pytest.raises(KeyError, match="Unknown analyzer"):
        registry._build_dependency_graph(["missing"])


def test_load_timestamp_ignores_invalid_types() -> None:
    result = AnalysisResult()
    before = result.timestamp

    _load_timestamp(result, {"timestamp": 1})
    _load_timestamp(result, {"timestamp": 123})

    assert result.timestamp == before


def test_load_timestamp_keeps_default_on_bad_string() -> None:
    result = AnalysisResult()
    before = result.timestamp

    _load_timestamp(result, {"timestamp": "not-a-date"})
    assert result.timestamp == before


def test_dict_to_model_non_strict_constructs_invalid_data() -> None:
    model = converters.dict_to_model(
        {"available": True, "hash_type": "not-a-thing"},
        HashAnalysisResult,
        strict=False,
    )
    assert isinstance(model, HashAnalysisResult)
    assert model.hash_type == "not-a-thing"


def test_convert_results_swallows_conversion_error_when_strict_false() -> None:
    class _ExplodingModel(BaseModel):  # pragma: no cover
        available: int

    converters.ResultConverter._schema_registry.clear()
    converters.ResultConverter.register_schema("broken", _ExplodingModel)

    converted = converters.ResultConverter.convert_results({"broken": "not-a-dict"}, strict=False)
    assert converted["broken"] == "not-a-dict"


def test_convert_results_raises_nothing_and_returns_raw_when_model_conversion_fails() -> None:
    class _ExplodingModel(BaseModel):
        available: int

    converters.ResultConverter._schema_registry.clear()
    converters.ResultConverter.register_schema("broken", _ExplodingModel)

    converted = converters.ResultConverter.convert_results(
        {"broken": "also-not-a-dict"}, strict=True
    )
    assert "broken" not in converted
