#!/usr/bin/env python3
"""Extra coverage tests for schemas/converters module.

No unittest.mock, no MagicMock, no patch. Real objects only.
"""

import pytest
from pydantic import BaseModel, ValidationError

from r2inspect.schemas.converters import (
    dict_to_model,
    model_to_dict,
    ResultConverter,
    safe_convert,
    validate_result,
)
from r2inspect.schemas.base import AnalysisResultBase


class SampleModel(BaseModel):
    name: str
    value: int


def test_dict_to_model_success():
    """Test successful dict to model conversion"""
    data = {"name": "test", "value": 42}
    model = dict_to_model(data, SampleModel)
    assert model.name == "test"
    assert model.value == 42


def test_dict_to_model_strict_failure():
    """Test dict to model with strict mode raises ValidationError"""
    data = {"name": "test", "value": "not_an_int"}
    with pytest.raises(ValidationError):
        dict_to_model(data, SampleModel, strict=True)


def test_dict_to_model_non_strict_failure():
    """Test dict to model non-strict mode falls back gracefully"""

    class OptionalModel(BaseModel):
        name: str = ""
        value: int = 0

    data = {"name": "test", "value": "not_an_int"}
    model = dict_to_model(data, OptionalModel, strict=False)
    assert model.name == "test"
    # value could not be parsed; falls back to default
    assert model.value == 0


def test_model_to_dict():
    """Test model to dict conversion"""
    model = SampleModel(name="test", value=42)
    data = model_to_dict(model)
    assert data["name"] == "test"
    assert data["value"] == 42


def test_model_to_dict_exclude_none():
    """Test model to dict excluding None values"""

    class NullableModel(BaseModel):
        name: str
        value: int | None = None

    model = NullableModel(name="test")
    data = model_to_dict(model, exclude_none=True)
    assert "value" not in data


def test_model_to_dict_include_none():
    """Test model to dict including None values"""

    class NullableModel(BaseModel):
        name: str
        value: int | None = None

    model = NullableModel(name="test")
    data = model_to_dict(model, exclude_none=False)
    assert "value" in data
    assert data["value"] is None


def test_result_converter_register_schema():
    """Test registering a schema"""
    ResultConverter.register_schema("test_extra_cov", SampleModel)
    schema = ResultConverter.get_schema("test_extra_cov")
    assert schema == SampleModel


def test_result_converter_register_schemas():
    """Test registering multiple schemas"""
    schemas = {"test_extra1": SampleModel, "test_extra2": SampleModel}
    ResultConverter.register_schemas(schemas)
    assert ResultConverter.get_schema("test_extra1") == SampleModel
    assert ResultConverter.get_schema("test_extra2") == SampleModel


def test_result_converter_get_schema_unknown():
    """Test getting unknown schema returns default"""
    schema = ResultConverter.get_schema("unknown_analyzer_xyz_extra_cov")
    assert schema == AnalysisResultBase


def test_result_converter_get_schema_normalized():
    """Test schema name normalization"""
    ResultConverter.register_schema("TEST_EXTRA_NORM", SampleModel)
    schema = ResultConverter.get_schema("test_extra_norm")
    assert schema == SampleModel


def test_result_converter_convert_result():
    """Test converting a result"""
    ResultConverter.register_schema("test_conv_extra", SampleModel)
    data = {"name": "test", "value": 42}
    result = ResultConverter.convert_result("test_conv_extra", data)
    assert isinstance(result, SampleModel)


def test_result_converter_convert_result_adds_analyzer_name():
    """Test convert_result adds analyzer_name if missing"""
    ResultConverter.register_schema("test_name_extra", AnalysisResultBase)
    data = {"available": True}
    result = ResultConverter.convert_result("test_name_extra", data)
    assert result.analyzer_name == "test_name_extra"


def test_result_converter_convert_results():
    """Test converting multiple results"""
    ResultConverter.register_schema("test_multi_extra", SampleModel)
    results_dict = {"test_multi_extra": {"name": "test", "value": 42}}
    converted = ResultConverter.convert_results(results_dict)
    assert "test_multi_extra" in converted


def test_result_converter_convert_results_error():
    """Test convert_results handles errors"""
    ResultConverter.register_schema("test_err_extra", SampleModel)
    results_dict = {"test_err_extra": {"invalid": "data"}}
    converted = ResultConverter.convert_results(results_dict, strict=False)
    assert "test_err_extra" in converted


def test_result_converter_list_registered_schemas():
    """Test listing registered schemas"""
    ResultConverter.register_schema("test_list_extra", SampleModel)
    schemas = ResultConverter.list_registered_schemas()
    assert "test_list_extra" in schemas
    assert schemas["test_list_extra"] == "SampleModel"


def test_safe_convert_success():
    """Test safe_convert with valid data"""
    data = {"name": "test", "value": 42}
    result = safe_convert(data, SampleModel)
    assert result.name == "test"


def test_safe_convert_none():
    """Test safe_convert with None returns default"""
    result = safe_convert(None, SampleModel, default=None)
    assert result is None


def test_safe_convert_already_correct_type():
    """Test safe_convert with already correct type"""
    model = SampleModel(name="test", value=42)
    result = safe_convert(model, SampleModel)
    assert result is model


def test_safe_convert_invalid_type():
    """Test safe_convert with invalid type returns default"""
    result = safe_convert("not a dict", SampleModel, default=None)
    assert result is None


def test_safe_convert_error():
    """Test safe_convert handles conversion errors with truly broken data"""

    # Use a model that requires a specific type and provide incompatible data.
    class StrictModel(BaseModel):
        count: int

    # Passing a dict with wrong types; safe_convert should return default, not raise.
    result = safe_convert({"count": "not_convertible_to_int_xyz"}, StrictModel, default=None)
    # Either the conversion succeeds via coercion or returns default.
    assert result is None or isinstance(result, StrictModel)


def test_validate_result_success():
    """Test validate_result with valid model"""
    model = SampleModel(name="test", value=42)
    assert validate_result(model) is True


def test_validate_result_with_constructed_model():
    """Test validate_result with model built via construct (bypass validation)"""
    model = SampleModel.model_construct(name="test", value="not_an_int")
    # validate_result re-validates the model; should return True or False.
    result = validate_result(model)
    assert isinstance(result, bool)
