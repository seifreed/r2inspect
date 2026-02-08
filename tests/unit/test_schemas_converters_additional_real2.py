from __future__ import annotations

import pytest
from pydantic import ValidationError

from r2inspect.schemas.base import AnalysisResultBase, FileInfoBase
from r2inspect.schemas.converters import (
    ResultConverter,
    dict_to_model,
    model_to_dict,
    safe_convert,
    validate_result,
)
from r2inspect.schemas.hashing import HashAnalysisResult


def test_base_schema_validators_and_dump() -> None:
    base = AnalysisResultBase(available=True, execution_time=0.1, analyzer_name=" PE ")
    assert base.analyzer_name == "pe"
    assert base.model_dump_safe()["available"] is True
    assert '"available":true' in base.to_json().lower()

    with pytest.raises(ValueError):
        AnalysisResultBase(available=True, execution_time=-1.0)

    info = FileInfoBase(file_extension=".EXE ")
    assert info.file_extension == "exe"


def test_hash_schema_validators_and_helpers() -> None:
    result = HashAnalysisResult(
        available=True,
        hash_type="SSDEEP",
        hash_value="3:abc:def",
        method_used="PYTHON_LIBRARY",
        file_size=123,
    )
    assert result.hash_type == "ssdeep"
    assert result.is_valid_hash() is True

    with pytest.raises(ValueError):
        HashAnalysisResult(available=True, hash_type="unknown")

    with pytest.raises(ValueError):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=-1)

    with pytest.raises(ValueError):
        HashAnalysisResult(
            available=True,
            hash_type="ssdeep",
            file_size=11 * 1024 * 1024 * 1024,
        )


def test_converters_strict_and_non_strict() -> None:
    data = {"available": True, "hash_type": "bad", "hash_value": "x"}
    with pytest.raises(ValidationError):
        dict_to_model(data, HashAnalysisResult, strict=True)

    model = dict_to_model(data, HashAnalysisResult, strict=False)
    assert isinstance(model, HashAnalysisResult)

    dumped = model_to_dict(model, exclude_none=True)
    assert dumped["hash_type"] == "bad"


def test_result_converter_and_safe_convert_paths() -> None:
    ResultConverter.register_schema("hash", HashAnalysisResult)
    schema = ResultConverter.get_schema("hash")
    assert schema is HashAnalysisResult

    converted = ResultConverter.convert_result(
        "hash",
        {"available": True, "hash_type": "ssdeep", "hash_value": "x"},
    )
    assert isinstance(converted, HashAnalysisResult)

    results = ResultConverter.convert_results(
        {
            "hash": {"available": True, "hash_type": "ssdeep", "hash_value": "x"},
            "bad": {"available": True, "hash_type": "bad"},
        },
        strict=False,
    )
    assert isinstance(results["hash"], HashAnalysisResult)
    assert isinstance(results["bad"], AnalysisResultBase)

    default = HashAnalysisResult(available=True, hash_type="ssdeep")
    assert safe_convert(None, HashAnalysisResult, default=default) is default
    assert safe_convert(default, HashAnalysisResult) is default
    assert safe_convert({"available": True, "hash_type": "ssdeep"}, HashAnalysisResult)
    assert safe_convert("bad", HashAnalysisResult, default=None) is None


def test_validate_result_error_path() -> None:
    bad_model = HashAnalysisResult.model_construct(
        available=True,
        hash_type="bad",
        hash_value="x",
    )
    assert validate_result(bad_model) is False
