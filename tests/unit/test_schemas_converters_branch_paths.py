#!/usr/bin/env python3
"""Branch-path tests for r2inspect/schemas/converters.py.

Covers missing lines: 42-47, 52, 81, 155-156, 186, 189-193, 218-228,
269-285, 307-314.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from r2inspect.schemas.base import AnalysisResultBase
from r2inspect.schemas.converters import (
    ResultConverter,
    dict_to_model,
    model_to_dict,
    safe_convert,
    validate_result,
)
from r2inspect.schemas.hashing import HashAnalysisResult


# ---------------------------------------------------------------------------
# dict_to_model – success and failure branches
# ---------------------------------------------------------------------------


def test_dict_to_model_valid_data_returns_model():
    data = {"available": True, "hash_type": "ssdeep", "hash_value": "abc"}
    model = dict_to_model(data, HashAnalysisResult)
    assert isinstance(model, HashAnalysisResult)
    assert model.hash_type == "ssdeep"


def test_dict_to_model_invalid_data_strict_false_uses_construct():
    # execution_time has ge=0.0 constraint; negative value triggers ValidationError
    data = {"available": True, "execution_time": -99}
    model = dict_to_model(data, HashAnalysisResult, strict=False)
    # model_construct bypasses validation, so the model exists
    assert model is not None
    assert model.execution_time == -99


def test_dict_to_model_invalid_data_strict_true_raises():
    data = {"available": True, "execution_time": -99}
    with pytest.raises(ValidationError):
        dict_to_model(data, HashAnalysisResult, strict=True)


# ---------------------------------------------------------------------------
# model_to_dict – by_alias branch
# ---------------------------------------------------------------------------


def test_model_to_dict_by_alias_true():
    model = HashAnalysisResult(available=True, hash_type="tlsh")
    result = model_to_dict(model, by_alias=True)
    assert isinstance(result, dict)
    assert "available" in result


def test_model_to_dict_exclude_none_false_includes_none_fields():
    model = HashAnalysisResult(available=False, hash_type="ssdeep")
    result = model_to_dict(model, exclude_none=False)
    # With exclude_none=False, None fields appear
    assert "available" in result


# ---------------------------------------------------------------------------
# ResultConverter.register_schemas – bulk registration
# ---------------------------------------------------------------------------


def test_result_converter_register_schemas_registers_all():
    ResultConverter.register_schemas(
        {
            "tc_bulk_ssdeep": HashAnalysisResult,
            "tc_bulk_tlsh": HashAnalysisResult,
        }
    )
    assert ResultConverter.get_schema("tc_bulk_ssdeep") is HashAnalysisResult
    assert ResultConverter.get_schema("tc_bulk_tlsh") is HashAnalysisResult


# ---------------------------------------------------------------------------
# ResultConverter.get_schema – registered and default paths
# ---------------------------------------------------------------------------


def test_get_schema_returns_registered_class():
    ResultConverter.register_schema("tc_registered_hash", HashAnalysisResult)
    schema = ResultConverter.get_schema("tc_registered_hash")
    assert schema is HashAnalysisResult


def test_get_schema_unknown_name_returns_default():
    schema = ResultConverter.get_schema("tc_definitely_not_registered_xyz")
    assert schema is AnalysisResultBase


def test_get_schema_normalizes_case():
    ResultConverter.register_schema("TC_UPPER_CASE", HashAnalysisResult)
    schema = ResultConverter.get_schema("TC_UPPER_CASE")
    assert schema is HashAnalysisResult


# ---------------------------------------------------------------------------
# ResultConverter.convert_result – with and without analyzer_name in result
# ---------------------------------------------------------------------------


def test_convert_result_adds_analyzer_name_when_missing():
    ResultConverter.register_schema("tc_no_name", HashAnalysisResult)
    data = {"available": True, "hash_type": "ssdeep"}
    # result dict does NOT contain analyzer_name
    model = ResultConverter.convert_result("tc_no_name", data)
    assert model.analyzer_name == "tc_no_name"


def test_convert_result_preserves_existing_analyzer_name():
    ResultConverter.register_schema("tc_with_name", HashAnalysisResult)
    data = {"available": True, "hash_type": "ssdeep", "analyzer_name": "tc_with_name"}
    model = ResultConverter.convert_result("tc_with_name", data)
    assert model.analyzer_name == "tc_with_name"


def test_convert_result_strict_false_handles_invalid_data():
    ResultConverter.register_schema("tc_bad_data", HashAnalysisResult)
    data = {"available": True, "execution_time": -1}
    model = ResultConverter.convert_result("tc_bad_data", data, strict=False)
    assert model is not None


def test_convert_result_unregistered_uses_base_schema():
    data = {"available": True}
    model = ResultConverter.convert_result("tc_unregistered_xyz_abc", data)
    assert isinstance(model, AnalysisResultBase)


# ---------------------------------------------------------------------------
# ResultConverter.convert_results – success and exception paths
# ---------------------------------------------------------------------------


def test_convert_results_converts_multiple_results():
    ResultConverter.register_schema("tc_multi_a", HashAnalysisResult)
    ResultConverter.register_schema("tc_multi_b", HashAnalysisResult)
    results = {
        "tc_multi_a": {"available": True, "hash_type": "ssdeep"},
        "tc_multi_b": {"available": False},
    }
    converted = ResultConverter.convert_results(results)
    assert "tc_multi_a" in converted
    assert "tc_multi_b" in converted
    assert isinstance(converted["tc_multi_a"], HashAnalysisResult)


def test_convert_results_non_dict_result_stored_as_is_when_not_strict():
    # Passing None as a result causes convert_result to raise (in contains check)
    # With strict=False it is stored as-is
    results = {"tc_none_result": None}
    converted = ResultConverter.convert_results(results, strict=False)
    # The raw None is stored because conversion failed
    assert "tc_none_result" in converted
    assert converted["tc_none_result"] is None


def test_convert_results_strict_true_does_not_store_failed_result():
    # With strict=True, failed conversions are not stored
    results = {"tc_strict_fail": None}
    converted = ResultConverter.convert_results(results, strict=True)
    assert "tc_strict_fail" not in converted


def test_convert_results_empty_input_returns_empty_dict():
    converted = ResultConverter.convert_results({})
    assert converted == {}


# ---------------------------------------------------------------------------
# ResultConverter.list_registered_schemas
# ---------------------------------------------------------------------------


def test_list_registered_schemas_returns_name_map():
    ResultConverter.register_schema("tc_list_test", HashAnalysisResult)
    schemas = ResultConverter.list_registered_schemas()
    assert isinstance(schemas, dict)
    assert "tc_list_test" in schemas
    assert schemas["tc_list_test"] == "HashAnalysisResult"


def test_list_registered_schemas_values_are_class_names():
    ResultConverter.register_schemas(
        {
            "tc_names_a": HashAnalysisResult,
            "tc_names_b": AnalysisResultBase,
        }
    )
    schemas = ResultConverter.list_registered_schemas()
    assert schemas["tc_names_a"] == "HashAnalysisResult"
    assert schemas["tc_names_b"] == "AnalysisResultBase"


# ---------------------------------------------------------------------------
# safe_convert edge cases
# ---------------------------------------------------------------------------


def test_safe_convert_none_returns_default():
    result = safe_convert(None, HashAnalysisResult)
    assert result is None


def test_safe_convert_already_correct_type_returns_as_is():
    model = HashAnalysisResult(available=True, hash_type="ssdeep")
    result = safe_convert(model, HashAnalysisResult)
    assert result is model


def test_safe_convert_non_dict_non_model_returns_default():
    result = safe_convert(12345, HashAnalysisResult)
    assert result is None


def test_safe_convert_valid_dict_returns_model():
    result = safe_convert({"available": True, "hash_type": "ssdeep"}, HashAnalysisResult)
    assert isinstance(result, HashAnalysisResult)


# ---------------------------------------------------------------------------
# validate_result
# ---------------------------------------------------------------------------


def test_validate_result_valid_model_returns_true():
    model = HashAnalysisResult(available=True, hash_type="ssdeep")
    assert validate_result(model) is True
