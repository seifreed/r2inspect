#!/usr/bin/env python3
"""Comprehensive tests for output_json.py to achieve 95%+ coverage."""

import json

import pytest

from r2inspect.utils.output_json import JsonOutputFormatter


def test_formatter_basic_dict():
    results = {"key": "value", "number": 42}
    formatter = JsonOutputFormatter(results)
    
    output = formatter.to_json()
    parsed = json.loads(output)
    
    assert parsed["key"] == "value"
    assert parsed["number"] == 42


def test_formatter_nested_dict():
    results = {
        "outer": {
            "inner": {
                "deep": "value"
            }
        },
        "list": [1, 2, 3]
    }
    formatter = JsonOutputFormatter(results)
    
    output = formatter.to_json()
    parsed = json.loads(output)
    
    assert parsed["outer"]["inner"]["deep"] == "value"
    assert parsed["list"] == [1, 2, 3]


def test_formatter_with_indent():
    results = {"a": 1, "b": 2}
    formatter = JsonOutputFormatter(results)
    
    output_2 = formatter.to_json(indent=2)
    output_4 = formatter.to_json(indent=4)
    
    assert len(output_4) > len(output_2)
    assert json.loads(output_2) == json.loads(output_4)


def test_formatter_default_str_conversion():
    class CustomObject:
        def __str__(self):
            return "custom_object"
    
    results = {"obj": CustomObject()}
    formatter = JsonOutputFormatter(results)
    
    output = formatter.to_json()
    parsed = json.loads(output)
    
    assert parsed["obj"] == "custom_object"


def test_formatter_with_none():
    results = {"value": None}
    formatter = JsonOutputFormatter(results)
    
    output = formatter.to_json()
    parsed = json.loads(output)
    
    assert parsed["value"] is None


def test_formatter_with_boolean():
    results = {"true": True, "false": False}
    formatter = JsonOutputFormatter(results)
    
    output = formatter.to_json()
    parsed = json.loads(output)
    
    assert parsed["true"] is True
    assert parsed["false"] is False


def test_formatter_with_numbers():
    results = {
        "int": 42,
        "float": 3.14,
        "negative": -100,
    }
    formatter = JsonOutputFormatter(results)
    
    output = formatter.to_json()
    parsed = json.loads(output)
    
    assert parsed["int"] == 42
    assert parsed["float"] == 3.14
    assert parsed["negative"] == -100


def test_formatter_with_lists():
    results = {
        "empty": [],
        "numbers": [1, 2, 3],
        "mixed": [1, "two", 3.0, None, True],
    }
    formatter = JsonOutputFormatter(results)
    
    output = formatter.to_json()
    parsed = json.loads(output)
    
    assert parsed["empty"] == []
    assert parsed["numbers"] == [1, 2, 3]
    assert parsed["mixed"] == [1, "two", 3.0, None, True]


def test_formatter_serialization_error():
    class NonSerializable:
        def __str__(self):
            raise ValueError("Cannot convert to string")
    
    results = {"obj": NonSerializable()}
    formatter = JsonOutputFormatter(results)
    
    output = formatter.to_json()
    parsed = json.loads(output)
    
    assert "error" in parsed
    assert "JSON serialization failed" in parsed["error"]
    assert "partial_results" in parsed


def test_formatter_empty_dict():
    results = {}
    formatter = JsonOutputFormatter(results)
    
    output = formatter.to_json()
    parsed = json.loads(output)
    
    assert parsed == {}


def test_formatter_large_dict():
    results = {f"key_{i}": i for i in range(1000)}
    formatter = JsonOutputFormatter(results)
    
    output = formatter.to_json()
    parsed = json.loads(output)
    
    assert len(parsed) == 1000
    assert parsed["key_0"] == 0
    assert parsed["key_999"] == 999


def test_formatter_unicode():
    results = {
        "english": "hello",
        "chinese": "你好",
        "emoji": "👍",
    }
    formatter = JsonOutputFormatter(results)
    
    output = formatter.to_json()
    parsed = json.loads(output)
    
    assert parsed["english"] == "hello"
    assert parsed["chinese"] == "你好"
    assert parsed["emoji"] == "👍"


def test_formatter_special_characters():
    results = {
        "quote": 'text with "quotes"',
        "newline": "line1\nline2",
        "tab": "text\twith\ttabs",
    }
    formatter = JsonOutputFormatter(results)
    
    output = formatter.to_json()
    parsed = json.loads(output)
    
    assert parsed["quote"] == 'text with "quotes"'
    assert parsed["newline"] == "line1\nline2"
    assert parsed["tab"] == "text\twith\ttabs"


def test_formatter_nested_lists():
    results = {
        "matrix": [[1, 2], [3, 4], [5, 6]]
    }
    formatter = JsonOutputFormatter(results)
    
    output = formatter.to_json()
    parsed = json.loads(output)
    
    assert parsed["matrix"] == [[1, 2], [3, 4], [5, 6]]


def test_formatter_mixed_nesting():
    results = {
        "data": {
            "users": [
                {"name": "Alice", "age": 30},
                {"name": "Bob", "age": 25}
            ],
            "meta": {
                "count": 2,
                "active": True
            }
        }
    }
    formatter = JsonOutputFormatter(results)
    
    output = formatter.to_json()
    parsed = json.loads(output)
    
    assert len(parsed["data"]["users"]) == 2
    assert parsed["data"]["users"][0]["name"] == "Alice"
    assert parsed["data"]["meta"]["count"] == 2
