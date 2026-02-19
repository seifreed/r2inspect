#!/usr/bin/env python3
"""Extra coverage tests for schemas/converters module."""

import pytest
from unittest.mock import MagicMock, patch
from pydantic import BaseModel, ValidationError

from r2inspect.schemas.converters import (
    dict_to_model,
    model_to_dict,
    ResultConverter,
    safe_convert,
    validate_result,
)
from r2inspect.schemas.base import AnalysisResultBase


class TestModel(BaseModel):
    name: str
    value: int


def test_dict_to_model_success():
    """Test successful dict to model conversion"""
    data = {"name": "test", "value": 42}
    model = dict_to_model(data, TestModel)
    assert model.name == "test"
    assert model.value == 42


def test_dict_to_model_strict_failure():
    """Test dict to model with strict mode raises ValidationError"""
    data = {"name": "test", "value": "not_an_int"}
    with pytest.raises(ValidationError):
        dict_to_model(data, TestModel, strict=True)


def test_dict_to_model_non_strict_failure():
    """Test dict to model non-strict mode uses construct"""
    data = {"name": "test", "value": "not_an_int"}
    model = dict_to_model(data, TestModel, strict=False)
    assert model.name == "test"


def test_model_to_dict():
    """Test model to dict conversion"""
    model = TestModel(name="test", value=42)
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
    ResultConverter.register_schema("test", TestModel)
    schema = ResultConverter.get_schema("test")
    assert schema == TestModel


def test_result_converter_register_schemas():
    """Test registering multiple schemas"""
    schemas = {"test1": TestModel, "test2": TestModel}
    ResultConverter.register_schemas(schemas)
    assert ResultConverter.get_schema("test1") == TestModel
    assert ResultConverter.get_schema("test2") == TestModel


def test_result_converter_get_schema_unknown():
    """Test getting unknown schema returns default"""
    schema = ResultConverter.get_schema("unknown_analyzer_xyz")
    assert schema == AnalysisResultBase


def test_result_converter_get_schema_normalized():
    """Test schema name normalization"""
    ResultConverter.register_schema("TEST", TestModel)
    schema = ResultConverter.get_schema("test")
    assert schema == TestModel


def test_result_converter_convert_result():
    """Test converting a result"""
    ResultConverter.register_schema("test_conv", TestModel)
    data = {"name": "test", "value": 42}
    result = ResultConverter.convert_result("test_conv", data)
    assert isinstance(result, TestModel)


def test_result_converter_convert_result_adds_analyzer_name():
    """Test convert_result adds analyzer_name if missing"""
    ResultConverter.register_schema("test_name", AnalysisResultBase)
    data = {"available": True}
    result = ResultConverter.convert_result("test_name", data)
    assert result.analyzer_name == "test_name"


def test_result_converter_convert_results():
    """Test converting multiple results"""
    ResultConverter.register_schema("test_multi", TestModel)
    results_dict = {
        "test_multi": {"name": "test", "value": 42}
    }
    converted = ResultConverter.convert_results(results_dict)
    assert "test_multi" in converted


def test_result_converter_convert_results_error():
    """Test convert_results handles errors"""
    ResultConverter.register_schema("test_err", TestModel)
    results_dict = {
        "test_err": {"invalid": "data"}
    }
    converted = ResultConverter.convert_results(results_dict, strict=False)
    assert "test_err" in converted


def test_result_converter_list_registered_schemas():
    """Test listing registered schemas"""
    ResultConverter.register_schema("test_list", TestModel)
    schemas = ResultConverter.list_registered_schemas()
    assert "test_list" in schemas
    assert schemas["test_list"] == "TestModel"


def test_safe_convert_success():
    """Test safe_convert with valid data"""
    data = {"name": "test", "value": 42}
    result = safe_convert(data, TestModel)
    assert result.name == "test"


def test_safe_convert_none():
    """Test safe_convert with None returns default"""
    result = safe_convert(None, TestModel, default=None)
    assert result is None


def test_safe_convert_already_correct_type():
    """Test safe_convert with already correct type"""
    model = TestModel(name="test", value=42)
    result = safe_convert(model, TestModel)
    assert result is model


def test_safe_convert_invalid_type():
    """Test safe_convert with invalid type returns default"""
    result = safe_convert("not a dict", TestModel, default=None)
    assert result is None


def test_safe_convert_error():
    """Test safe_convert handles conversion errors"""
    data = {"invalid": "data"}
    # Test with truly invalid data
    with patch("r2inspect.schemas.converters.dict_to_model", side_effect=Exception("error")):
        result = safe_convert({"test": "data"}, TestModel, default=None)
    assert result is None


def test_validate_result_success():
    """Test validate_result with valid model"""
    model = TestModel(name="test", value=42)
    assert validate_result(model) is True


def test_validate_result_failure():
    """Test validate_result with invalid model"""
    class BadModel(BaseModel):
        name: str
        value: int
    
    # Create an invalid model using construct (bypassing validation)
    model = BadModel.model_construct(name="test", value="not_an_int")
    
    # This should fail when re-validated
    with patch.object(BadModel, '__init__', side_effect=ValidationError.from_exception_data("test", [])):
        result = validate_result(model)
        # The function catches ValidationError, so it should return False
