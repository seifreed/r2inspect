from __future__ import annotations

import pytest
from pydantic import BaseModel, Field, ValidationError

from r2inspect.schemas.converters import (
    ResultConverter,
    dict_to_model,
    model_to_dict,
    safe_convert,
    validate_result,
)
from r2inspect.schemas.hashing import HashAnalysisResult


class ExplodingModel(BaseModel):
    x: int = Field(...)

    def __init__(self, **data: object) -> None:
        raise RuntimeError("boom")


def test_dict_to_model_strict_and_non_strict() -> None:
    data = {"available": True, "hash_type": "invalid"}
    model = dict_to_model(data, HashAnalysisResult, strict=False)
    assert model.hash_type == "invalid"

    with pytest.raises(ValidationError):
        dict_to_model(data, HashAnalysisResult, strict=True)


def test_model_to_dict_exclude_none() -> None:
    model = HashAnalysisResult(available=True, hash_type="ssdeep")
    data = model_to_dict(model)
    assert "hash_type" in data
    assert "method_used" not in data


def test_result_converter_registration_and_conversion() -> None:
    ResultConverter.register_schema("ssdeep", HashAnalysisResult)
    schema = ResultConverter.get_schema("SSDEEP")
    assert schema is HashAnalysisResult

    result = ResultConverter.convert_result(
        "ssdeep", {"available": True, "hash_type": "ssdeep", "hash_value": "x"}
    )
    assert isinstance(result, HashAnalysisResult)
    assert result.analyzer_name == "ssdeep"

    converted = ResultConverter.convert_results(
        {
            "ssdeep": {"available": True, "hash_type": "ssdeep", "hash_value": "x"},
            "bad": {"available": True, "hash_type": "nope"},
        }
    )
    assert isinstance(converted["ssdeep"], BaseModel)
    assert isinstance(converted["bad"], BaseModel)

    names = ResultConverter.list_registered_schemas()
    assert "ssdeep" in names


def test_safe_convert_and_validate_result() -> None:
    model = HashAnalysisResult(available=True, hash_type="ssdeep")
    assert safe_convert(model, HashAnalysisResult) is model
    assert safe_convert(None, HashAnalysisResult, default=model) is model
    assert safe_convert("nope", HashAnalysisResult) is None

    bad = safe_convert({"available": True, "hash_type": "nope"}, HashAnalysisResult)
    assert bad is not None

    assert safe_convert({"x": 1}, ExplodingModel) is None

    invalid = HashAnalysisResult.model_construct(available=True, hash_type="nope")
    assert validate_result(invalid) is False
    assert validate_result(model) is True
