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


def test_dict_to_model_strict_validation():
    data = {"available": True, "hash_type": "ssdeep", "hash_value": "x"}
    model = dict_to_model(data, HashAnalysisResult, strict=True)
    assert isinstance(model, HashAnalysisResult)

    with pytest.raises(ValidationError):
        dict_to_model({"available": True, "hash_type": "bad"}, HashAnalysisResult, strict=True)


def test_model_to_dict_exclude_none():
    model = HashAnalysisResult(available=True, hash_type="ssdeep")
    data = model_to_dict(model)
    assert "hash_value" not in data


def test_result_converter_register_and_convert():
    ResultConverter.register_schema("ssdeep", HashAnalysisResult)
    data = {"available": True, "hash_type": "ssdeep", "hash_value": "abc"}
    model = ResultConverter.convert_result("ssdeep", data)
    assert isinstance(model, HashAnalysisResult)
    assert model.analyzer_name == "ssdeep"


def test_safe_convert_and_validate():
    model = safe_convert({"available": True, "hash_type": "ssdeep"}, HashAnalysisResult)
    assert isinstance(model, HashAnalysisResult)
    assert validate_result(model) is True

    assert safe_convert("bad", HashAnalysisResult) is None
