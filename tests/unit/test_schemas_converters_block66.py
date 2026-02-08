from __future__ import annotations

import pytest
from pydantic import ValidationError

from r2inspect.schemas.converters import (
    ResultConverter,
    dict_to_model,
    model_to_dict,
    safe_convert,
    validate_result,
)
from r2inspect.schemas.hashing import HashAnalysisResult


def test_dict_to_model_strict_and_non_strict():
    data = {"available": True, "hash_type": "invalid", "hash_value": "x"}

    with pytest.raises(ValidationError):
        dict_to_model(data, HashAnalysisResult, strict=True)

    model = dict_to_model(data, HashAnalysisResult, strict=False)
    assert isinstance(model, HashAnalysisResult)
    assert model.hash_type == "invalid"


def test_model_to_dict_exclude_none_false():
    result = HashAnalysisResult(available=True, hash_type="ssdeep", method_used=None)
    dumped = model_to_dict(result, exclude_none=False)
    assert "method_used" in dumped


def test_result_converter_and_list_registered():
    ResultConverter.register_schema("ssdeep", HashAnalysisResult)
    schema = ResultConverter.get_schema("ssdeep")
    assert schema is HashAnalysisResult

    unknown = ResultConverter.get_schema("unknown")
    assert unknown.__name__ == "AnalysisResultBase"

    result = ResultConverter.convert_result(
        "ssdeep", {"available": True, "hash_type": "ssdeep"}, strict=True
    )
    assert result.analyzer_name == "ssdeep"

    listed = ResultConverter.list_registered_schemas()
    assert listed["ssdeep"] == "HashAnalysisResult"


def test_convert_results_error_path_non_dict():
    results = {"ssdeep": "not a dict"}
    converted = ResultConverter.convert_results(results, strict=False)
    assert converted["ssdeep"] == "not a dict"


def test_safe_convert_paths_and_validate_result():
    default = HashAnalysisResult(available=True, hash_type="ssdeep")
    assert safe_convert(None, HashAnalysisResult, default=default) is default

    existing = HashAnalysisResult(available=True, hash_type="tlsh")
    assert safe_convert(existing, HashAnalysisResult) is existing

    invalid = safe_convert("string", HashAnalysisResult, default=None)
    assert invalid is None

    constructed = HashAnalysisResult.model_construct(
        available=True, hash_type="invalid", hash_value="x"
    )
    assert validate_result(constructed) is False
