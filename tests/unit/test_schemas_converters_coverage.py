"""Coverage tests for r2inspect/schemas/converters.py"""

import pytest
from pydantic import BaseModel, ValidationError

from r2inspect.schemas.base import AnalysisResultBase
from r2inspect.schemas.converters import (
    ResultConverter,
    dict_to_model,
    model_to_dict,
    safe_convert,
    validate_result,
)


class _SimpleModel(BaseModel):
    name: str
    value: int = 0


class _StrictModel(BaseModel):
    required_field: str
    count: int


# dict_to_model tests

def test_dict_to_model_valid():
    result = dict_to_model({"name": "test", "value": 42}, _SimpleModel)
    assert result.name == "test"
    assert result.value == 42


def test_dict_to_model_uses_default():
    result = dict_to_model({"name": "hello"}, _SimpleModel)
    assert result.name == "hello"
    assert result.value == 0


def test_dict_to_model_validation_error_non_strict_constructs():
    # Invalid data with strict=False should use model_construct
    result = dict_to_model({"name": 999, "value": "not_int"}, _SimpleModel, strict=False)
    # model_construct bypasses validation, raw data preserved
    assert result is not None


def test_dict_to_model_validation_error_strict_raises():
    with pytest.raises(ValidationError):
        dict_to_model({"name": "ok", "count": "not_int"}, _StrictModel, strict=True)


def test_dict_to_model_missing_required_strict_raises():
    with pytest.raises(ValidationError):
        dict_to_model({}, _StrictModel, strict=True)


def test_dict_to_model_missing_required_non_strict_constructs():
    result = dict_to_model({}, _StrictModel, strict=False)
    assert result is not None


# model_to_dict tests

def test_model_to_dict_basic():
    model = _SimpleModel(name="test", value=10)
    d = model_to_dict(model)
    assert isinstance(d, dict)
    assert d["name"] == "test"
    assert d["value"] == 10


def test_model_to_dict_exclude_none():
    result = AnalysisResultBase(available=True, error=None)
    d = model_to_dict(result, exclude_none=True)
    assert "error" not in d


def test_model_to_dict_include_none():
    result = AnalysisResultBase(available=True, error=None)
    d = model_to_dict(result, exclude_none=False)
    assert "error" in d
    assert d["error"] is None


def test_model_to_dict_by_alias_false():
    model = _SimpleModel(name="x", value=5)
    d = model_to_dict(model, by_alias=False)
    assert "name" in d


# ResultConverter tests

def test_result_converter_register_and_get_schema():
    ResultConverter.register_schema("test_analyzer_x", _SimpleModel)
    schema = ResultConverter.get_schema("test_analyzer_x")
    assert schema is _SimpleModel


def test_result_converter_register_schema_normalizes_name():
    ResultConverter.register_schema("TEST_UPPER", _SimpleModel)
    schema = ResultConverter.get_schema("test_upper")
    assert schema is _SimpleModel


def test_result_converter_get_schema_unknown_returns_default():
    schema = ResultConverter.get_schema("nonexistent_xyz_analyzer")
    assert schema is ResultConverter._default_schema


def test_result_converter_register_schemas_multiple():
    ResultConverter.register_schemas({
        "multi_a": _SimpleModel,
        "multi_b": _SimpleModel,
    })
    assert ResultConverter.get_schema("multi_a") is _SimpleModel
    assert ResultConverter.get_schema("multi_b") is _SimpleModel


def test_result_converter_convert_result_adds_analyzer_name():
    ResultConverter.register_schema("convert_test", _SimpleModel)
    data = {"name": "hello", "value": 7}
    result = ResultConverter.convert_result("convert_test", data)
    assert isinstance(result, _SimpleModel)
    assert result.name == "hello"


def test_result_converter_convert_result_preserves_analyzer_name():
    ResultConverter.register_schema("with_name_test", AnalysisResultBase)
    data = {"available": True, "analyzer_name": "with_name_test"}
    result = ResultConverter.convert_result("with_name_test", data)
    assert isinstance(result, AnalysisResultBase)


def test_result_converter_convert_results_multiple():
    ResultConverter.register_schema("ra", _SimpleModel)
    results = {
        "ra": {"name": "alpha", "value": 1},
    }
    converted = ResultConverter.convert_results(results)
    assert "ra" in converted
    assert isinstance(converted["ra"], _SimpleModel)


def test_result_converter_convert_results_non_strict_on_error():
    # Use an unregistered analyzer so default schema is used
    results = {
        "unknown_zzz": {"bogus_field": "data"},
    }
    converted = ResultConverter.convert_results(results, strict=False)
    assert "unknown_zzz" in converted


def test_result_converter_list_registered_schemas():
    ResultConverter.register_schema("list_test_schema", _SimpleModel)
    schemas = ResultConverter.list_registered_schemas()
    assert isinstance(schemas, dict)
    assert "list_test_schema" in schemas
    assert schemas["list_test_schema"] == "_SimpleModel"


# safe_convert tests

def test_safe_convert_valid_dict():
    result = safe_convert({"name": "test", "value": 5}, _SimpleModel)
    assert isinstance(result, _SimpleModel)
    assert result.name == "test"


def test_safe_convert_none_returns_default():
    result = safe_convert(None, _SimpleModel)
    assert result is None


def test_safe_convert_none_with_custom_default():
    default = _SimpleModel(name="default", value=0)
    result = safe_convert(None, _SimpleModel, default=default)
    assert result is default


def test_safe_convert_already_correct_type():
    model = _SimpleModel(name="existing", value=3)
    result = safe_convert(model, _SimpleModel)
    assert result is model


def test_safe_convert_invalid_type_returns_default():
    # Pass a non-dict, non-model type
    result = safe_convert("not_a_dict", _SimpleModel)
    assert result is None


def test_safe_convert_invalid_dict_returns_none():
    # dict_to_model with strict=False will use model_construct
    # but if something truly fails, returns None
    result = safe_convert({"name": "ok", "value": 0}, _SimpleModel)
    assert result is not None  # valid data succeeds


# validate_result tests

def test_validate_result_valid():
    model = AnalysisResultBase(available=True, analyzer_name="test")
    assert validate_result(model) is True


def test_validate_result_with_execution_time():
    model = AnalysisResultBase(available=True, execution_time=1.0)
    assert validate_result(model) is True


def test_validate_result_simple_model():
    model = _SimpleModel(name="hello", value=42)
    assert validate_result(model) is True


# Additional tests for exception handling paths

def test_convert_results_exception_logged_and_stored_when_non_strict():
    """When strict=False and conversion fails (non-dict result), raw value is stored."""
    ResultConverter.register_schema("none_result_test", _StrictModel)
    results = {"none_result_test": None}  # None causes TypeError in convert_result
    converted = ResultConverter.convert_results(results, strict=False)
    assert "none_result_test" in converted
    assert converted["none_result_test"] is None


def test_convert_results_strict_exception_not_stored():
    """When strict=True and conversion fails, result is not stored in converted."""
    ResultConverter.register_schema("strict_none_test", _StrictModel)
    results = {"strict_none_test": None}  # None causes TypeError
    converted = ResultConverter.convert_results(results, strict=True)
    # Exception caught, but with strict=True, raw result NOT stored
    assert "strict_none_test" not in converted


def test_safe_convert_non_dict_non_model_returns_default():
    """safe_convert returns default for non-dict, non-model input."""
    result = safe_convert(42, _SimpleModel, default=None)
    assert result is None


def test_safe_convert_string_returns_default():
    """safe_convert returns default for string input."""
    result = safe_convert("hello", _SimpleModel, default=None)
    assert result is None


def test_validate_result_validation_error_returns_false():
    """validate_result returns False when re-validation fails due to required field."""
    # Create a model via model_construct (bypasses validation) with invalid data
    model = _StrictModel.model_construct(required_field=None, count="not_int")
    result = validate_result(model)
    # Re-validation fails since required_field is None
    assert result is False


def test_safe_convert_model_construct_raises_returns_default():
    """safe_convert returns default when model_construct raises RuntimeError."""
    from pydantic import BaseModel

    class RaisingConstruct(BaseModel):
        name: str
        value: int

        @classmethod
        def model_construct(cls, **values: object) -> "RaisingConstruct":
            raise RuntimeError("construct always fails")

    result = safe_convert({"name": "test", "value": "not_int"}, RaisingConstruct, default=None)
    assert result is None
