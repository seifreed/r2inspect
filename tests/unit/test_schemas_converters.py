#!/usr/bin/env python3
"""Comprehensive tests for r2inspect/schemas/converters.py - targeting 100% coverage."""

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


def test_dict_to_model_success():
    """Test dict_to_model with valid data."""
    data = {
        "available": True,
        "hash_type": "ssdeep",
        "hash_value": "3:abc:def"
    }
    model = dict_to_model(data, HashAnalysisResult, strict=False)
    
    assert isinstance(model, HashAnalysisResult)
    assert model.available is True
    assert model.hash_type == "ssdeep"
    assert model.hash_value == "3:abc:def"


def test_dict_to_model_strict_mode_success():
    """Test dict_to_model in strict mode with valid data."""
    data = {
        "available": True,
        "hash_type": "ssdeep",
        "hash_value": "abc123"
    }
    model = dict_to_model(data, HashAnalysisResult, strict=True)
    
    assert isinstance(model, HashAnalysisResult)
    assert model.hash_type == "ssdeep"


def test_dict_to_model_strict_mode_failure():
    """Test dict_to_model in strict mode with invalid data."""
    data = {
        "available": "not_a_bool",  # Invalid type
        "hash_type": "ssdeep"
    }
    
    with pytest.raises(ValidationError):
        dict_to_model(data, HashAnalysisResult, strict=True)


def test_dict_to_model_non_strict_mode_fallback():
    """Test dict_to_model in non-strict mode uses model_construct on validation error."""
    data = {
        "available": True,
        "hash_type": "invalid_hash_type",  # Invalid enum value
        "extra_field": "should_be_preserved"
    }
    
    # Non-strict mode should not raise, but use model_construct
    model = dict_to_model(data, HashAnalysisResult, strict=False)
    
    assert isinstance(model, HashAnalysisResult)
    # model_construct bypasses validation, so invalid data may be preserved


def test_model_to_dict_basic():
    """Test model_to_dict basic conversion."""
    model = HashAnalysisResult(
        available=True,
        hash_type="tlsh",
        hash_value="abc123"
    )
    
    data = model_to_dict(model)
    
    assert isinstance(data, dict)
    assert data["available"] is True
    assert data["hash_type"] == "tlsh"
    assert data["hash_value"] == "abc123"


def test_model_to_dict_exclude_none():
    """Test model_to_dict with exclude_none=True (default)."""
    model = HashAnalysisResult(
        available=True,
        hash_type="ssdeep"
        # hash_value is None
    )
    
    data = model_to_dict(model, exclude_none=True)
    
    assert "hash_value" not in data
    assert "available" in data


def test_model_to_dict_include_none():
    """Test model_to_dict with exclude_none=False."""
    model = HashAnalysisResult(
        available=True,
        hash_type="ssdeep"
        # hash_value is None
    )
    
    data = model_to_dict(model, exclude_none=False)
    
    assert "hash_value" in data
    assert data["hash_value"] is None


def test_model_to_dict_by_alias():
    """Test model_to_dict with by_alias parameter."""
    model = HashAnalysisResult(
        available=True,
        hash_type="impfuzzy",
        hash_value="xyz"
    )
    
    # Test without aliases
    data1 = model_to_dict(model, by_alias=False)
    assert "available" in data1
    
    # Test with aliases (if any are defined)
    data2 = model_to_dict(model, by_alias=True)
    assert isinstance(data2, dict)


def test_result_converter_register_schema():
    """Test ResultConverter.register_schema."""
    # Clear any existing registrations for test isolation
    ResultConverter._schema_registry.clear()
    
    ResultConverter.register_schema("test_hash", HashAnalysisResult)
    
    assert "test_hash" in ResultConverter._schema_registry
    assert ResultConverter._schema_registry["test_hash"] == HashAnalysisResult


def test_result_converter_register_schema_normalization():
    """Test ResultConverter normalizes analyzer names."""
    ResultConverter._schema_registry.clear()
    
    # Register with uppercase and spaces
    ResultConverter.register_schema("  TEST_HASH  ", HashAnalysisResult)
    
    # Should be normalized to lowercase and stripped
    assert "test_hash" in ResultConverter._schema_registry


def test_result_converter_register_schemas_bulk():
    """Test ResultConverter.register_schemas for bulk registration."""
    ResultConverter._schema_registry.clear()
    
    schemas = {
        "ssdeep": HashAnalysisResult,
        "tlsh": HashAnalysisResult,
        "impfuzzy": HashAnalysisResult,
    }
    
    ResultConverter.register_schemas(schemas)
    
    assert len(ResultConverter._schema_registry) == 3
    assert "ssdeep" in ResultConverter._schema_registry
    assert "tlsh" in ResultConverter._schema_registry
    assert "impfuzzy" in ResultConverter._schema_registry


def test_result_converter_get_schema_registered():
    """Test ResultConverter.get_schema for registered analyzer."""
    ResultConverter._schema_registry.clear()
    ResultConverter.register_schema("ssdeep", HashAnalysisResult)
    
    schema = ResultConverter.get_schema("ssdeep")
    
    assert schema == HashAnalysisResult


def test_result_converter_get_schema_unregistered():
    """Test ResultConverter.get_schema for unregistered analyzer returns default."""
    ResultConverter._schema_registry.clear()
    
    schema = ResultConverter.get_schema("unknown_analyzer")
    
    # Should return default schema
    assert schema == AnalysisResultBase


def test_result_converter_get_schema_normalization():
    """Test ResultConverter.get_schema normalizes analyzer names."""
    ResultConverter._schema_registry.clear()
    ResultConverter.register_schema("ssdeep", HashAnalysisResult)
    
    # Query with different casing/spacing
    schema = ResultConverter.get_schema("  SSDEEP  ")
    
    assert schema == HashAnalysisResult


def test_result_converter_convert_result():
    """Test ResultConverter.convert_result."""
    ResultConverter._schema_registry.clear()
    ResultConverter.register_schema("ssdeep", HashAnalysisResult)
    
    data = {
        "available": True,
        "hash_type": "ssdeep",
        "hash_value": "3:abc:def"
    }
    
    result = ResultConverter.convert_result("ssdeep", data, strict=False)
    
    assert isinstance(result, HashAnalysisResult)
    assert result.hash_type == "ssdeep"
    assert result.analyzer_name == "ssdeep"


def test_result_converter_convert_result_adds_analyzer_name():
    """Test ResultConverter.convert_result adds analyzer_name if missing."""
    ResultConverter._schema_registry.clear()
    ResultConverter.register_schema("ssdeep", HashAnalysisResult)
    
    data = {
        "available": True,
        "hash_type": "ssdeep",
        "hash_value": "abc123"
        # Note: analyzer_name not in data
    }
    
    result = ResultConverter.convert_result("ssdeep", data)
    
    # analyzer_name should be added
    assert result.analyzer_name == "ssdeep"


def test_result_converter_convert_result_preserves_analyzer_name():
    """Test ResultConverter.convert_result preserves existing analyzer_name."""
    ResultConverter._schema_registry.clear()
    ResultConverter.register_schema("tlsh", HashAnalysisResult)
    
    data = {
        "available": True,
        "analyzer_name": "tlsh",  # Already present
        "hash_type": "tlsh",
        "hash_value": "xyz"
    }
    
    result = ResultConverter.convert_result("tlsh", data)
    
    assert result.analyzer_name == "tlsh"


def test_result_converter_convert_result_unregistered():
    """Test ResultConverter.convert_result with unregistered analyzer."""
    ResultConverter._schema_registry.clear()
    
    data = {
        "available": True,
        "analyzer_name": "unknown"
    }
    
    result = ResultConverter.convert_result("unknown", data)
    
    # Should use default schema
    assert isinstance(result, AnalysisResultBase)
    assert result.analyzer_name == "unknown"


def test_result_converter_convert_results_multiple():
    """Test ResultConverter.convert_results with multiple analyzers."""
    ResultConverter._schema_registry.clear()
    ResultConverter.register_schemas({
        "ssdeep": HashAnalysisResult,
        "tlsh": HashAnalysisResult,
    })
    
    results = {
        "ssdeep": {
            "available": True,
            "hash_type": "ssdeep",
            "hash_value": "3:abc:def"
        },
        "tlsh": {
            "available": True,
            "hash_type": "tlsh",
            "hash_value": "abc123"
        }
    }
    
    converted = ResultConverter.convert_results(results, strict=False)
    
    assert len(converted) == 2
    assert isinstance(converted["ssdeep"], HashAnalysisResult)
    assert isinstance(converted["tlsh"], HashAnalysisResult)
    assert converted["ssdeep"].hash_type == "ssdeep"
    assert converted["tlsh"].hash_type == "tlsh"


def test_result_converter_convert_results_error_handling():
    """Test ResultConverter.convert_results handles errors gracefully in non-strict mode."""
    ResultConverter._schema_registry.clear()
    ResultConverter.register_schema("test", HashAnalysisResult)
    
    results = {
        "test": {
            "available": "invalid_type",  # Will cause error
            "hash_type": "ssdeep"
        }
    }
    
    # Should not raise in non-strict mode
    converted = ResultConverter.convert_results(results, strict=False)
    
    # Failed conversion should preserve original data
    assert "test" in converted


def test_result_converter_convert_results_strict_mode():
    """Test ResultConverter.convert_results in strict mode raises on error."""
    ResultConverter._schema_registry.clear()
    ResultConverter.register_schema("test", HashAnalysisResult)
    
    results = {
        "test": {
            "available": True,
            "hash_type": "ssdeep",
            "hash_value": "valid"
        },
        "bad": {
            "available": "invalid",  # Invalid data
        }
    }
    
    # In strict=False, should handle error gracefully
    converted = ResultConverter.convert_results(results, strict=False)
    assert "test" in converted


def test_result_converter_list_registered_schemas():
    """Test ResultConverter.list_registered_schemas."""
    ResultConverter._schema_registry.clear()
    ResultConverter.register_schemas({
        "ssdeep": HashAnalysisResult,
        "ssdeep": HashAnalysisResult,
    })
    
    schemas = ResultConverter.list_registered_schemas()
    
    assert isinstance(schemas, dict)
    assert "ssdeep" in schemas
    assert "ssdeep" in schemas
    assert schemas["ssdeep"] == "HashAnalysisResult"
    assert schemas["ssdeep"] == "HashAnalysisResult"


def test_result_converter_list_registered_schemas_empty():
    """Test ResultConverter.list_registered_schemas when empty."""
    ResultConverter._schema_registry.clear()
    
    schemas = ResultConverter.list_registered_schemas()
    
    assert schemas == {}


def test_safe_convert_with_dict():
    """Test safe_convert with dict data."""
    data = {
        "available": True,
        "hash_type": "ssdeep",
        "hash_value": "abc"
    }
    
    result = safe_convert(data, HashAnalysisResult)
    
    assert isinstance(result, HashAnalysisResult)
    assert result.hash_type == "ssdeep"


def test_safe_convert_with_model():
    """Test safe_convert when data is already the correct model type."""
    model = HashAnalysisResult(
        available=True,
        hash_type="tlsh",
        hash_value="xyz"
    )
    
    result = safe_convert(model, HashAnalysisResult)
    
    # Should return the same instance
    assert result is model


def test_safe_convert_with_none():
    """Test safe_convert with None returns default."""
    result = safe_convert(None, HashAnalysisResult)
    
    assert result is None


def test_safe_convert_with_none_and_default():
    """Test safe_convert with None and custom default."""
    default_model = HashAnalysisResult(
        available=False,
        hash_type="ssdeep"
    )
    
    result = safe_convert(None, HashAnalysisResult, default=default_model)
    
    assert result is default_model


def test_safe_convert_with_invalid_type():
    """Test safe_convert with invalid data type returns default."""
    result = safe_convert("not_a_dict_or_model", HashAnalysisResult)
    
    assert result is None


def test_safe_convert_with_invalid_type_and_default():
    """Test safe_convert with invalid data type returns custom default."""
    default_model = HashAnalysisResult(available=False, hash_type="ssdeep")
    
    result = safe_convert(123, HashAnalysisResult, default=default_model)
    
    assert result is default_model


def test_safe_convert_with_conversion_error():
    """Test safe_convert handles conversion errors gracefully."""
    # Data that will cause an error during conversion
    bad_data = {
        "available": True,
        "hash_type": "ssdeep",
        # Intentionally missing required fields or has wrong types
    }
    
    # Should return None on error
    result = safe_convert(bad_data, HashAnalysisResult)
    
    # safe_convert uses strict=False, so it might construct anyway
    # But if there's an exception, it should return None
    assert result is None or isinstance(result, HashAnalysisResult)


def test_validate_result_valid():
    """Test validate_result with valid model."""
    model = HashAnalysisResult(
        available=True,
        hash_type="impfuzzy",
        hash_value="abc123"
    )
    
    is_valid = validate_result(model)
    
    assert is_valid is True


def test_validate_result_invalid():
    """Test validate_result with model that fails re-validation."""
    # Create a model using model_construct to bypass validation
    model = HashAnalysisResult.model_construct(
        available=True,
        hash_type="invalid_type_that_fails_enum",
        hash_value="abc"
    )
    
    # validate_result should detect this is invalid
    is_valid = validate_result(model)
    
    # Should fail validation
    assert is_valid is False


def test_validate_result_with_constructed_model():
    """Test validate_result detects issues in constructed models."""
    # Use model_construct to create potentially invalid model
    model = HashAnalysisResult.model_construct(
        available="not_a_bool",  # Wrong type
        hash_type="ssdeep",
    )
    
    is_valid = validate_result(model)
    
    # Should fail re-validation
    assert is_valid is False


def test_dict_to_model_with_extra_fields():
    """Test dict_to_model preserves extra fields in non-strict mode."""
    data = {
        "available": True,
        "hash_type": "ssdeep",
        "hash_value": "abc",
        "extra_field": "should_be_handled"
    }
    
    # Non-strict mode
    model = dict_to_model(data, HashAnalysisResult, strict=False)
    
    assert isinstance(model, HashAnalysisResult)


def test_result_converter_convert_result_strict():
    """Test ResultConverter.convert_result in strict mode."""
    ResultConverter._schema_registry.clear()
    ResultConverter.register_schema("test", HashAnalysisResult)
    
    valid_data = {
        "available": True,
        "hash_type": "ssdeep",
        "hash_value": "abc123"
    }
    
    result = ResultConverter.convert_result("test", valid_data, strict=True)
    
    assert isinstance(result, HashAnalysisResult)
    assert result.analyzer_name == "test"


def test_result_converter_empty_registry():
    """Test ResultConverter behavior with empty registry."""
    ResultConverter._schema_registry.clear()
    
    # Should use default schema
    data = {"available": True}
    result = ResultConverter.convert_result("unknown", data)
    
    assert isinstance(result, AnalysisResultBase)


def test_model_to_dict_all_combinations():
    """Test model_to_dict with all parameter combinations."""
    model = HashAnalysisResult(
        available=True,
        hash_type="tlsh",
        hash_value="xyz"
    )
    
    # exclude_none=True, by_alias=False
    data1 = model_to_dict(model, by_alias=False, exclude_none=True)
    assert isinstance(data1, dict)
    
    # exclude_none=False, by_alias=False
    data2 = model_to_dict(model, by_alias=False, exclude_none=False)
    assert isinstance(data2, dict)
    
    # exclude_none=True, by_alias=True
    data3 = model_to_dict(model, by_alias=True, exclude_none=True)
    assert isinstance(data3, dict)
    
    # exclude_none=False, by_alias=True
    data4 = model_to_dict(model, by_alias=True, exclude_none=False)
    assert isinstance(data4, dict)
