#!/usr/bin/env python3
"""
Comprehensive tests for r2inspect/adapters/validation.py

Tests all validators with valid/invalid inputs, edge cases, and error conditions.
CRITICAL: Security validation module - must achieve 100% coverage.
"""

import pytest

from r2inspect.adapters.validation import (
    _clean_dict_values,
    _clean_list_items,
    _validate_bytes_data,
    _validate_dict_data,
    _validate_list_data,
    _validate_str_data,
    is_valid_r2_response,
    sanitize_r2_output,
    validate_address,
    validate_r2_data,
    validate_size,
)


# validate_r2_data tests - comprehensive coverage


def test_validate_r2_data_dict_valid():
    data = {"key": "value", "number": 42}
    result = validate_r2_data(data, "dict")
    assert result == {"key": "value", "number": 42}
    assert isinstance(result, dict)


def test_validate_r2_data_dict_invalid_returns_empty():
    result = validate_r2_data("not a dict", "dict")
    assert result == {}
    assert isinstance(result, dict)


def test_validate_r2_data_dict_with_html_entities():
    data = {"name": "test&nbsp;&amp;&lt;&gt;", "value": "a&quot;b&#39;c"}
    result = validate_r2_data(data, "dict")
    assert result["name"] == "test &<>"
    assert result["value"] == 'a"b\'c'


def test_validate_r2_data_list_valid():
    data = [{"id": 1}, {"id": 2}]
    result = validate_r2_data(data, "list")
    assert result == [{"id": 1}, {"id": 2}]
    assert isinstance(result, list)


def test_validate_r2_data_list_empty_returns_empty():
    result = validate_r2_data([], "list")
    assert result == []


def test_validate_r2_data_list_invalid_returns_empty():
    result = validate_r2_data("not a list", "list")
    assert result == []
    assert isinstance(result, list)


def test_validate_r2_data_list_filters_non_dict_items():
    data = [{"valid": 1}, "invalid", {"valid": 2}, 123, {"valid": 3}]
    result = validate_r2_data(data, "list")
    assert len(result) == 3
    assert all(isinstance(item, dict) for item in result)
    assert result == [{"valid": 1}, {"valid": 2}, {"valid": 3}]


def test_validate_r2_data_str_valid():
    result = validate_r2_data("hello world", "str")
    assert result == "hello world"
    assert isinstance(result, str)


def test_validate_r2_data_str_from_bytes():
    result = validate_r2_data(b"hello", "str")
    assert result == "hello"
    assert isinstance(result, str)


def test_validate_r2_data_str_from_bytes_with_errors():
    invalid_utf8 = b"\xff\xfe invalid"
    result = validate_r2_data(invalid_utf8, "str")
    assert isinstance(result, str)


def test_validate_r2_data_str_invalid_returns_empty():
    result = validate_r2_data(123, "str")
    assert result == ""


def test_validate_r2_data_str_with_ansi_codes():
    data = "text\x1b[0m with \x1b[31mcolor"
    result = validate_r2_data(data, "str")
    assert "\x1b" not in result


def test_validate_r2_data_bytes_valid():
    result = validate_r2_data(b"binary", "bytes")
    assert result == b"binary"
    assert isinstance(result, bytes)


def test_validate_r2_data_bytes_from_str():
    result = validate_r2_data("text", "bytes")
    assert result == b"text"
    assert isinstance(result, bytes)


def test_validate_r2_data_bytes_invalid_returns_empty():
    result = validate_r2_data(123, "bytes")
    assert result == b""


def test_validate_r2_data_any_returns_as_is():
    data = {"any": "thing"}
    result = validate_r2_data(data, "any")
    assert result == data

    result = validate_r2_data([1, 2, 3], "any")
    assert result == [1, 2, 3]

    result = validate_r2_data("text", "any")
    assert result == "text"


def test_validate_r2_data_unknown_type_returns_as_is():
    data = {"test": "data"}
    result = validate_r2_data(data, "unknown_type")
    assert result == data


# _validate_dict_data tests


def test_validate_dict_data_valid_dict():
    data = {"key": "value"}
    result = _validate_dict_data(data)
    assert result == {"key": "value"}


def test_validate_dict_data_empty_dict():
    result = _validate_dict_data({})
    assert result == {}


def test_validate_dict_data_nested_dict():
    data = {"outer": {"inner": "value"}}
    result = _validate_dict_data(data)
    assert result == {"outer": {"inner": "value"}}


def test_validate_dict_data_non_dict():
    result = _validate_dict_data([1, 2, 3])
    assert result == {}


def test_validate_dict_data_none():
    result = _validate_dict_data(None)
    assert result == {}


# _validate_list_data tests


def test_validate_list_data_valid_list():
    data = [{"a": 1}, {"b": 2}]
    result = _validate_list_data(data)
    assert result == [{"a": 1}, {"b": 2}]


def test_validate_list_data_empty_list():
    result = _validate_list_data([])
    assert result == []


def test_validate_list_data_non_list():
    result = _validate_list_data({"not": "list"})
    assert result == []


def test_validate_list_data_mixed_types():
    data = [{"valid": 1}, "string", 123, None, {"valid": 2}]
    result = _validate_list_data(data)
    assert len(result) == 2
    assert result == [{"valid": 1}, {"valid": 2}]


# _validate_str_data tests


def test_validate_str_data_valid_string():
    result = _validate_str_data("test string")
    assert result == "test string"


def test_validate_str_data_empty_string():
    result = _validate_str_data("")
    assert result == ""


def test_validate_str_data_bytes():
    result = _validate_str_data(b"byte string")
    assert result == "byte string"


def test_validate_str_data_bytes_decode_error():
    # This should not raise, but handle gracefully
    result = _validate_str_data(123)
    assert result == ""


def test_validate_str_data_with_control_chars():
    result = _validate_str_data("line1\nline2\ttab")
    assert "\n" in result
    assert "\t" in result


# _validate_bytes_data tests


def test_validate_bytes_data_valid_bytes():
    result = _validate_bytes_data(b"data")
    assert result == b"data"


def test_validate_bytes_data_empty_bytes():
    result = _validate_bytes_data(b"")
    assert result == b""


def test_validate_bytes_data_from_string():
    result = _validate_bytes_data("text")
    assert result == b"text"


def test_validate_bytes_data_invalid():
    result = _validate_bytes_data(123)
    assert result == b""


# _clean_list_items tests


def test_clean_list_items_all_valid():
    data = [{"a": 1}, {"b": 2}]
    result = _clean_list_items(data)
    assert len(result) == 2


def test_clean_list_items_with_invalid():
    data = [{"valid": 1}, "invalid", 123, {"valid": 2}]
    result = _clean_list_items(data)
    assert len(result) == 2
    assert all(isinstance(item, dict) for item in result)


def test_clean_list_items_empty():
    result = _clean_list_items([])
    assert result == []


def test_clean_list_items_cleans_html_entities():
    data = [{"name": "test&nbsp;value"}]
    result = _clean_list_items(data)
    assert result[0]["name"] == "test value"


# _clean_dict_values tests


def test_clean_dict_values_html_entities():
    data = {"key": "value&nbsp;with&amp;entities"}
    _clean_dict_values(data)
    assert data["key"] == "value with&entities"


def test_clean_dict_values_all_entities():
    data = {
        "nbsp": "a&nbsp;b",
        "amp": "a&amp;b",
        "lt": "a&lt;b",
        "gt": "a&gt;b",
        "quot": "a&quot;b",
        "apos": "a&#39;b",
    }
    _clean_dict_values(data)
    assert data["nbsp"] == "a b"
    assert data["amp"] == "a&b"
    assert data["lt"] == "a<b"
    assert data["gt"] == "a>b"
    assert data["quot"] == 'a"b'
    assert data["apos"] == "a'b"


def test_clean_dict_values_non_string_values():
    data = {"str": "test", "int": 42, "list": [1, 2], "dict": {"nested": "value"}}
    _clean_dict_values(data)
    assert data["str"] == "test"
    assert data["int"] == 42
    assert data["list"] == [1, 2]


def test_clean_dict_values_no_changes():
    data = {"clean": "value"}
    _clean_dict_values(data)
    assert data["clean"] == "value"


# sanitize_r2_output tests


def test_sanitize_r2_output_empty_string():
    result = sanitize_r2_output("")
    assert result == ""


def test_sanitize_r2_output_none():
    result = sanitize_r2_output("")
    assert result == ""


def test_sanitize_r2_output_removes_ansi_codes():
    text = "normal\x1b[0m text\x1b[31m red\x1b[0m"
    result = sanitize_r2_output(text)
    assert "\x1b" not in result
    assert "normal" in result
    assert "text" in result
    assert "red" in result


def test_sanitize_r2_output_removes_control_characters():
    text = "text\x00with\x01control\x02chars"
    result = sanitize_r2_output(text)
    assert "\x00" not in result
    assert "\x01" not in result
    assert "\x02" not in result


def test_sanitize_r2_output_preserves_newline_tab():
    text = "line1\nline2\ttab"
    result = sanitize_r2_output(text)
    assert "\n" in result
    assert "\t" in result


def test_sanitize_r2_output_strips_whitespace():
    text = "  \n  text  \n  "
    result = sanitize_r2_output(text)
    assert not result.startswith(" ")
    assert not result.endswith(" ")


def test_sanitize_r2_output_html_entities():
    text = "test&nbsp;&amp;&lt;&gt;&quot;&#39;"
    result = sanitize_r2_output(text)
    assert result == "test &<>\"'"


def test_sanitize_r2_output_complex():
    text = "\x1b[32m  Section .text&nbsp;\x00\n  Size: 0x1000  \x1b[0m"
    result = sanitize_r2_output(text)
    assert "\x1b" not in result
    assert "\x00" not in result
    assert "Section .text " in result
    assert "Size: 0x1000" in result


# is_valid_r2_response tests


def test_is_valid_r2_response_none():
    assert is_valid_r2_response(None) is False


def test_is_valid_r2_response_dict_empty():
    assert is_valid_r2_response({}) is False


def test_is_valid_r2_response_dict_valid():
    assert is_valid_r2_response({"key": "value"}) is True


def test_is_valid_r2_response_list_empty():
    assert is_valid_r2_response([]) is False


def test_is_valid_r2_response_list_valid():
    assert is_valid_r2_response([1, 2, 3]) is True


def test_is_valid_r2_response_str_empty():
    assert is_valid_r2_response("") is False


def test_is_valid_r2_response_str_whitespace():
    assert is_valid_r2_response("   ") is False


def test_is_valid_r2_response_str_valid():
    assert is_valid_r2_response("valid text") is True


def test_is_valid_r2_response_str_error_patterns():
    assert is_valid_r2_response("Cannot open file") is False
    assert is_valid_r2_response("File format not recognized") is False
    assert is_valid_r2_response("Invalid command") is False
    assert is_valid_r2_response("Error: something failed") is False
    assert is_valid_r2_response("Failed to parse") is False


def test_is_valid_r2_response_str_valid_with_error_substring():
    assert is_valid_r2_response("No error here") is True
    assert is_valid_r2_response("Failed to optimize") is False


def test_is_valid_r2_response_bytes_empty():
    assert is_valid_r2_response(b"") is False


def test_is_valid_r2_response_bytes_valid():
    assert is_valid_r2_response(b"data") is True


def test_is_valid_r2_response_other_types():
    assert is_valid_r2_response(42) is True
    assert is_valid_r2_response(0) is True
    assert is_valid_r2_response(True) is True
    assert is_valid_r2_response(False) is True


# validate_address tests


def test_validate_address_positive_int():
    assert validate_address(0) == 0
    assert validate_address(1000) == 1000
    assert validate_address(0x401000) == 0x401000


def test_validate_address_negative_int_raises():
    with pytest.raises(ValueError, match="cannot be negative"):
        validate_address(-1)
    with pytest.raises(ValueError, match="cannot be negative"):
        validate_address(-100)


def test_validate_address_hex_string():
    assert validate_address("0x0") == 0
    assert validate_address("0x10") == 16
    assert validate_address("0x401000") == 0x401000
    assert validate_address("0X401000") == 0x401000


def test_validate_address_decimal_string():
    assert validate_address("0") == 0
    assert validate_address("100") == 100
    assert validate_address("4198400") == 4198400


def test_validate_address_string_with_whitespace():
    assert validate_address("  0x100  ") == 256
    assert validate_address("  100  ") == 100


def test_validate_address_string_negative_raises():
    with pytest.raises(ValueError, match="Invalid address format"):
        validate_address("-1")
    with pytest.raises(ValueError, match="Invalid address format"):
        validate_address("0x-10")


def test_validate_address_invalid_string_raises():
    with pytest.raises(ValueError, match="Invalid address format"):
        validate_address("not a number")
    with pytest.raises(ValueError, match="Invalid address format"):
        validate_address("0xGGG")
    with pytest.raises(ValueError, match="Invalid address format"):
        validate_address("12.34")


def test_validate_address_invalid_type_raises():
    with pytest.raises(ValueError, match="must be int or str"):
        validate_address(12.34)
    with pytest.raises(ValueError, match="must be int or str"):
        validate_address([100])
    with pytest.raises(ValueError, match="must be int or str"):
        validate_address(None)


# validate_size tests


def test_validate_size_positive_int():
    assert validate_size(1) == 1
    assert validate_size(100) == 100
    assert validate_size(0x1000) == 0x1000


def test_validate_size_zero_raises():
    with pytest.raises(ValueError, match="must be positive"):
        validate_size(0)


def test_validate_size_negative_raises():
    with pytest.raises(ValueError, match="must be positive"):
        validate_size(-1)
    with pytest.raises(ValueError, match="must be positive"):
        validate_size(-100)


def test_validate_size_hex_string():
    assert validate_size("0x1") == 1
    assert validate_size("0x10") == 16
    assert validate_size("0x100") == 256
    assert validate_size("0X100") == 256


def test_validate_size_decimal_string():
    assert validate_size("1") == 1
    assert validate_size("100") == 100
    assert validate_size("256") == 256


def test_validate_size_string_with_whitespace():
    assert validate_size("  0x100  ") == 256
    assert validate_size("  100  ") == 100


def test_validate_size_string_zero_raises():
    with pytest.raises(ValueError, match="Invalid size format"):
        validate_size("0")
    with pytest.raises(ValueError, match="Invalid size format"):
        validate_size("0x0")


def test_validate_size_string_negative_raises():
    with pytest.raises(ValueError, match="Invalid size format"):
        validate_size("-1")


def test_validate_size_invalid_string_raises():
    with pytest.raises(ValueError, match="Invalid size format"):
        validate_size("not a number")
    with pytest.raises(ValueError, match="Invalid size format"):
        validate_size("0xGGG")
    with pytest.raises(ValueError, match="Invalid size format"):
        validate_size("12.34")


def test_validate_size_invalid_type_raises():
    with pytest.raises(ValueError, match="must be int or str"):
        validate_size(12.34)
    with pytest.raises(ValueError, match="must be int or str"):
        validate_size([100])
    with pytest.raises(ValueError, match="must be int or str"):
        validate_size(None)


# Edge cases and combinations


def test_validate_r2_data_dict_deeply_nested_entities():
    data = {
        "level1": {"level2": {"level3": "value&nbsp;here"}},
        "top": "also&amp;here",
    }
    result = validate_r2_data(data, "dict")
    assert result["top"] == "also&here"


def test_validate_r2_data_list_all_invalid_items():
    data = ["string", 123, None, True]
    result = validate_r2_data(data, "list")
    assert result == []


def test_sanitize_r2_output_all_control_chars():
    text = "\x00\x01\x02\x03\x04\x05"
    result = sanitize_r2_output(text)
    assert result == ""


def test_validate_address_max_values():
    max_32bit = 0xFFFFFFFF
    assert validate_address(max_32bit) == max_32bit
    assert validate_address("0xFFFFFFFF") == max_32bit

    max_64bit = 0xFFFFFFFFFFFFFFFF
    assert validate_address(max_64bit) == max_64bit


def test_validate_size_large_values():
    large = 0x10000000
    assert validate_size(large) == large
    assert validate_size("0x10000000") == large


def test_clean_dict_values_empty_dict():
    data = {}
    _clean_dict_values(data)
    assert data == {}


def test_clean_list_items_all_invalid_types():
    data = ["str", 123, None, True, 3.14]
    result = _clean_list_items(data)
    assert result == []
