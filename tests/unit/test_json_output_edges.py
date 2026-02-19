#!/usr/bin/env python3
"""Edge case tests for JsonOutputFormatter - 100% coverage."""

import json
from datetime import datetime
from decimal import Decimal

import pytest

from r2inspect.utils.output_json import JsonOutputFormatter


def test_empty_dict():
    """Test with empty dictionary."""
    formatter = JsonOutputFormatter({})
    result = formatter.to_json()
    assert json.loads(result) == {}


def test_nested_dict():
    """Test with nested dictionaries."""
    data = {
        "level1": {
            "level2": {
                "level3": "value"
            }
        }
    }
    formatter = JsonOutputFormatter(data)
    result = formatter.to_json()
    assert json.loads(result) == data


def test_list_values():
    """Test with list values."""
    data = {
        "items": [1, 2, 3],
        "names": ["a", "b", "c"]
    }
    formatter = JsonOutputFormatter(data)
    result = formatter.to_json()
    assert json.loads(result) == data


def test_mixed_types():
    """Test with mixed data types."""
    data = {
        "string": "text",
        "integer": 42,
        "float": 3.14,
        "boolean": True,
        "null": None
    }
    formatter = JsonOutputFormatter(data)
    result = formatter.to_json()
    assert json.loads(result) == data


def test_custom_indent_2():
    """Test with indent=2."""
    formatter = JsonOutputFormatter({"key": "value"})
    result = formatter.to_json(indent=2)
    assert "\n" in result
    parsed = json.loads(result)
    assert parsed == {"key": "value"}


def test_custom_indent_4():
    """Test with indent=4."""
    formatter = JsonOutputFormatter({"key": "value"})
    result = formatter.to_json(indent=4)
    assert "\n" in result
    parsed = json.loads(result)
    assert parsed == {"key": "value"}


def test_indent_none():
    """Test with indent=None (compact)."""
    formatter = JsonOutputFormatter({"key": "value"})
    result = formatter.to_json(indent=None)
    assert json.loads(result) == {"key": "value"}


def test_non_serializable_object():
    """Test with non-serializable object triggers error handling."""
    class CustomClass:
        def __str__(self):
            return "custom_string"
    
    obj = CustomClass()
    formatter = JsonOutputFormatter({"obj": obj})
    result = formatter.to_json()
    parsed = json.loads(result)
    # When non-serializable is encountered, str() is called
    assert parsed == {"obj": "custom_string"}


def test_serialization_error_handling():
    """Test exception handling when serialization fails."""
    class BadObject:
        def __str__(self):
            raise RuntimeError("Cannot convert to string")
    
    formatter = JsonOutputFormatter({"bad": BadObject()})
    result = formatter.to_json()
    parsed = json.loads(result)
    
    # Should have error key and partial_results
    assert "error" in parsed
    assert "JSON serialization failed" in parsed["error"]
    assert "partial_results" in parsed


def test_datetime_object():
    """Test with datetime object."""
    dt = datetime(2025, 1, 1, 12, 0, 0)
    formatter = JsonOutputFormatter({"timestamp": dt})
    result = formatter.to_json()
    parsed = json.loads(result)
    # datetime gets converted via str()
    assert "2025-01-01" in parsed["timestamp"]


def test_decimal_object():
    """Test with Decimal object."""
    dec = Decimal("123.45")
    formatter = JsonOutputFormatter({"amount": dec})
    result = formatter.to_json()
    parsed = json.loads(result)
    # Decimal gets converted via str()
    assert "123.45" in str(parsed["amount"])


def test_large_indent():
    """Test with large indent value."""
    formatter = JsonOutputFormatter({"a": 1})
    result = formatter.to_json(indent=20)
    parsed = json.loads(result)
    assert parsed == {"a": 1}


def test_unicode_strings():
    """Test with unicode characters."""
    data = {
        "emoji": "🔍",
        "chinese": "中文",
        "arabic": "العربية",
        "greek": "ελληνικά"
    }
    formatter = JsonOutputFormatter(data)
    result = formatter.to_json()
    parsed = json.loads(result)
    assert parsed == data


def test_special_characters():
    """Test with special characters that need escaping."""
    data = {
        "quote": 'He said "hello"',
        "backslash": "C:\\path\\to\\file",
        "newline": "line1\nline2",
        "tab": "col1\tcol2"
    }
    formatter = JsonOutputFormatter(data)
    result = formatter.to_json()
    parsed = json.loads(result)
    assert parsed == data


def test_very_large_dict():
    """Test with large dictionary."""
    data = {f"key_{i}": f"value_{i}" for i in range(1000)}
    formatter = JsonOutputFormatter(data)
    result = formatter.to_json()
    parsed = json.loads(result)
    assert len(parsed) == 1000
    assert parsed["key_500"] == "value_500"


def test_deeply_nested_structure():
    """Test with deeply nested structure."""
    data = {"level": 0}
    current = data
    for i in range(1, 50):
        current["nested"] = {"level": i}
        current = current["nested"]
    
    formatter = JsonOutputFormatter(data)
    result = formatter.to_json()
    parsed = json.loads(result)
    assert parsed["level"] == 0


def test_mixed_list_and_dict():
    """Test with mixed list and dict structures."""
    data = {
        "users": [
            {"id": 1, "name": "Alice"},
            {"id": 2, "name": "Bob"}
        ],
        "metadata": {
            "count": 2,
            "tags": ["active", "verified"]
        }
    }
    formatter = JsonOutputFormatter(data)
    result = formatter.to_json()
    parsed = json.loads(result)
    assert parsed == data


def test_boolean_values():
    """Test with boolean values."""
    data = {
        "active": True,
        "deleted": False,
        "verified": True
    }
    formatter = JsonOutputFormatter(data)
    result = formatter.to_json()
    parsed = json.loads(result)
    assert parsed == data


def test_numeric_edge_cases():
    """Test with numeric edge cases."""
    data = {
        "zero": 0,
        "negative": -42,
        "large": 999999999999,
        "float_zero": 0.0,
        "small_float": 0.00001
    }
    formatter = JsonOutputFormatter(data)
    result = formatter.to_json()
    parsed = json.loads(result)
    assert parsed == data


def test_null_values_in_dict():
    """Test with null values in nested structures."""
    data = {
        "field1": None,
        "field2": {
            "nested_null": None,
            "nested_value": "value"
        },
        "list_with_nulls": [1, None, 3]
    }
    formatter = JsonOutputFormatter(data)
    result = formatter.to_json()
    parsed = json.loads(result)
    assert parsed == data
