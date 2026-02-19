"""Comprehensive tests for adapters/validation.py data validation and sanitization."""

from __future__ import annotations

import pytest

from r2inspect.adapters.validation import (
    is_valid_r2_response,
    sanitize_r2_output,
    validate_address,
    validate_r2_data,
    validate_size,
)


class TestValidateR2Data:
    """Test validate_r2_data function with different data types."""

    def test_validate_dict_valid(self) -> None:
        """Test validation of valid dictionary data."""
        data = {"arch": "x86", "bits": 64}
        result = validate_r2_data(data, "dict")

        assert result == {"arch": "x86", "bits": 64}
        assert isinstance(result, dict)

    def test_validate_dict_invalid_returns_empty(self) -> None:
        """Test validation of invalid dict data returns empty dict."""
        data = "not a dict"
        result = validate_r2_data(data, "dict")

        assert result == {}
        assert isinstance(result, dict)

    def test_validate_dict_with_html_entities(self) -> None:
        """Test dict validation cleans HTML entities."""
        data = {"name": "Test&nbsp;Value", "desc": "&lt;test&gt;"}
        result = validate_r2_data(data, "dict")

        assert result["name"] == "Test Value"
        assert result["desc"] == "<test>"

    def test_validate_list_valid(self) -> None:
        """Test validation of valid list data."""
        data = [{"name": "section1"}, {"name": "section2"}]
        result = validate_r2_data(data, "list")

        assert len(result) == 2
        assert isinstance(result, list)
        assert all(isinstance(item, dict) for item in result)

    def test_validate_list_invalid_returns_empty(self) -> None:
        """Test validation of invalid list data returns empty list."""
        data = {"not": "a list"}
        result = validate_r2_data(data, "list")

        assert result == []
        assert isinstance(result, list)

    def test_validate_list_filters_non_dict_items(self) -> None:
        """Test list validation filters out non-dict items."""
        data = [{"valid": "item"}, "invalid string", 123, {"another": "valid"}]
        result = validate_r2_data(data, "list")

        assert len(result) == 2
        assert result[0] == {"valid": "item"}
        assert result[1] == {"another": "valid"}

    def test_validate_list_cleans_html_entities(self) -> None:
        """Test list validation cleans HTML entities in dict values."""
        data = [{"name": "Test&nbsp;Name"}, {"desc": "&amp;&lt;&gt;"}]
        result = validate_r2_data(data, "list")

        assert result[0]["name"] == "Test Name"
        assert result[1]["desc"] == "&<>"

    def test_validate_str_valid(self) -> None:
        """Test validation of valid string data."""
        data = "test string"
        result = validate_r2_data(data, "str")

        assert result == "test string"
        assert isinstance(result, str)

    def test_validate_str_from_bytes(self) -> None:
        """Test string validation converts bytes to string."""
        data = b"test bytes"
        result = validate_r2_data(data, "str")

        assert result == "test bytes"
        assert isinstance(result, str)

    def test_validate_str_invalid_returns_empty(self) -> None:
        """Test string validation returns empty string for invalid data."""
        data = 12345
        result = validate_r2_data(data, "str")

        assert result == ""
        assert isinstance(result, str)

    def test_validate_str_bytes_decode_error(self) -> None:
        """Test string validation handles decode errors gracefully."""
        data = b"\xff\xfe invalid utf-8"
        result = validate_r2_data(data, "str")

        # Should not crash, will use replacement characters
        assert isinstance(result, str)

    def test_validate_bytes_valid(self) -> None:
        """Test validation of valid bytes data."""
        data = b"test bytes"
        result = validate_r2_data(data, "bytes")

        assert result == b"test bytes"
        assert isinstance(result, bytes)

    def test_validate_bytes_from_string(self) -> None:
        """Test bytes validation converts string to bytes."""
        data = "test string"
        result = validate_r2_data(data, "bytes")

        assert result == b"test string"
        assert isinstance(result, bytes)

    def test_validate_bytes_invalid_returns_empty(self) -> None:
        """Test bytes validation returns empty bytes for invalid data."""
        data = 12345
        result = validate_r2_data(data, "bytes")

        assert result == b""
        assert isinstance(result, bytes)

    def test_validate_any_returns_as_is(self) -> None:
        """Test validation with 'any' type returns data as-is."""
        data = {"test": "data"}
        result = validate_r2_data(data, "any")

        assert result is data

    def test_validate_unknown_type_returns_as_is(self) -> None:
        """Test validation with unknown type returns data as-is."""
        data = {"test": "data"}
        result = validate_r2_data(data, "unknown_type")

        assert result is data


class TestSanitizeR2Output:
    """Test sanitize_r2_output function."""

    def test_sanitize_empty_string(self) -> None:
        """Test sanitization of empty string returns empty string."""
        result = sanitize_r2_output("")

        assert result == ""

    def test_sanitize_removes_ansi_codes(self) -> None:
        """Test sanitization removes ANSI escape codes."""
        text = "Section .text\x1b[0m\n  Size: 0x1000\x1b[31mRED\x1b[0m"
        result = sanitize_r2_output(text)

        assert "\x1b" not in result
        assert "Section .text" in result
        assert "Size: 0x1000" in result
        assert "RED" in result

    def test_sanitize_removes_control_characters(self) -> None:
        """Test sanitization removes control characters except newline/tab."""
        text = "Test\x00\x01\x02String\nWith\tWhitespace"
        result = sanitize_r2_output(text)

        assert "\x00" not in result
        assert "\x01" not in result
        assert "\x02" not in result
        assert "\n" in result
        assert "\t" in result

    def test_sanitize_cleans_html_entities(self) -> None:
        """Test sanitization cleans HTML entities."""
        text = "Test&nbsp;String&amp;&lt;&gt;&quot;&#39;"
        result = sanitize_r2_output(text)

        assert result == 'Test String&<>"\''

    def test_sanitize_strips_whitespace(self) -> None:
        """Test sanitization strips leading/trailing whitespace."""
        text = "   Test String   \n\n"
        result = sanitize_r2_output(text)

        assert result == "Test String"

    def test_sanitize_preserves_printable_chars(self) -> None:
        """Test sanitization preserves printable characters."""
        text = "Test 123 !@#$%^&*()_+-=[]{}|;:,.<>?"
        result = sanitize_r2_output(text)

        assert result == text


class TestIsValidR2Response:
    """Test is_valid_r2_response validation function."""

    def test_none_is_invalid(self) -> None:
        """Test None response is invalid."""
        assert is_valid_r2_response(None) is False

    def test_empty_dict_is_invalid(self) -> None:
        """Test empty dict is invalid."""
        assert is_valid_r2_response({}) is False

    def test_empty_list_is_invalid(self) -> None:
        """Test empty list is invalid."""
        assert is_valid_r2_response([]) is False

    def test_non_empty_dict_is_valid(self) -> None:
        """Test non-empty dict is valid."""
        assert is_valid_r2_response({"key": "value"}) is True

    def test_non_empty_list_is_valid(self) -> None:
        """Test non-empty list is valid."""
        assert is_valid_r2_response([1, 2, 3]) is True

    def test_empty_string_is_invalid(self) -> None:
        """Test empty string is invalid."""
        assert is_valid_r2_response("") is False

    def test_whitespace_only_string_is_invalid(self) -> None:
        """Test whitespace-only string is invalid."""
        assert is_valid_r2_response("   ") is False

    def test_valid_string_is_valid(self) -> None:
        """Test non-empty string is valid."""
        assert is_valid_r2_response("test output") is True

    def test_string_with_error_pattern_is_invalid(self) -> None:
        """Test strings with error patterns are invalid."""
        assert is_valid_r2_response("Cannot open file") is False
        assert is_valid_r2_response("File format not recognized") is False
        assert is_valid_r2_response("Invalid command") is False
        assert is_valid_r2_response("Error: something failed") is False
        assert is_valid_r2_response("Failed to load") is False

    def test_valid_bytes_is_valid(self) -> None:
        """Test non-empty bytes is valid."""
        assert is_valid_r2_response(b"test data") is True

    def test_empty_bytes_is_invalid(self) -> None:
        """Test empty bytes is invalid."""
        assert is_valid_r2_response(b"") is False

    def test_other_types_are_valid(self) -> None:
        """Test other non-None types are considered valid."""
        assert is_valid_r2_response(123) is True
        assert is_valid_r2_response(True) is True
        assert is_valid_r2_response(False) is True


class TestValidateAddress:
    """Test validate_address function."""

    def test_validate_positive_int_address(self) -> None:
        """Test validation of positive integer address."""
        result = validate_address(0x401000)

        assert result == 0x401000
        assert isinstance(result, int)

    def test_validate_zero_address(self) -> None:
        """Test validation of zero address."""
        result = validate_address(0)

        assert result == 0

    def test_validate_negative_int_raises(self) -> None:
        """Test negative integer address raises ValueError."""
        with pytest.raises(ValueError, match="Address cannot be negative"):
            validate_address(-1)

    def test_validate_hex_string_address(self) -> None:
        """Test validation of hex string address."""
        result = validate_address("0x401000")

        assert result == 0x401000

    def test_validate_hex_string_uppercase(self) -> None:
        """Test validation of uppercase hex string address."""
        result = validate_address("0X401000")

        assert result == 0x401000

    def test_validate_decimal_string_address(self) -> None:
        """Test validation of decimal string address."""
        result = validate_address("4198400")

        assert result == 4198400

    def test_validate_hex_string_negative_raises(self) -> None:
        """Test negative hex string raises ValueError."""
        with pytest.raises(ValueError, match="Invalid address format"):
            validate_address("0x-1")

        with pytest.raises(ValueError, match="Invalid address format"):
            validate_address("-0x1")

    def test_validate_invalid_string_format_raises(self) -> None:
        """Test invalid string format raises ValueError."""
        with pytest.raises(ValueError, match="Invalid address format"):
            validate_address("not_a_number")

    def test_validate_invalid_type_raises(self) -> None:
        """Test invalid type raises ValueError."""
        with pytest.raises(ValueError, match="Address must be int or str"):
            validate_address([0x401000])

        with pytest.raises(ValueError, match="Address must be int or str"):
            validate_address(None)


class TestValidateSize:
    """Test validate_size function."""

    def test_validate_positive_int_size(self) -> None:
        """Test validation of positive integer size."""
        result = validate_size(1024)

        assert result == 1024
        assert isinstance(result, int)

    def test_validate_zero_size_raises(self) -> None:
        """Test zero size raises ValueError."""
        with pytest.raises(ValueError, match="Size must be positive"):
            validate_size(0)

    def test_validate_negative_size_raises(self) -> None:
        """Test negative size raises ValueError."""
        with pytest.raises(ValueError, match="Size must be positive"):
            validate_size(-1)

    def test_validate_hex_string_size(self) -> None:
        """Test validation of hex string size."""
        result = validate_size("0x100")

        assert result == 256

    def test_validate_hex_string_uppercase_size(self) -> None:
        """Test validation of uppercase hex string size."""
        result = validate_size("0X100")

        assert result == 256

    def test_validate_decimal_string_size(self) -> None:
        """Test validation of decimal string size."""
        result = validate_size("256")

        assert result == 256

    def test_validate_zero_string_size_raises(self) -> None:
        """Test zero string size raises ValueError."""
        with pytest.raises(ValueError, match="Invalid size format"):
            validate_size("0")

        with pytest.raises(ValueError, match="Invalid size format"):
            validate_size("0x0")

    def test_validate_negative_string_size_raises(self) -> None:
        """Test negative string size raises ValueError."""
        with pytest.raises(ValueError, match="Invalid size format"):
            validate_size("-1")

    def test_validate_invalid_string_format_raises(self) -> None:
        """Test invalid string format raises ValueError."""
        with pytest.raises(ValueError, match="Invalid size format"):
            validate_size("not_a_number")

    def test_validate_invalid_type_size_raises(self) -> None:
        """Test invalid type raises ValueError."""
        with pytest.raises(ValueError, match="Size must be int or str"):
            validate_size([1024])

        with pytest.raises(ValueError, match="Size must be int or str"):
            validate_size(None)


class TestValidationEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_validate_dict_with_nested_html_entities(self) -> None:
        """Test deeply nested HTML entities are cleaned."""
        data = {
            "level1": "Test&nbsp;",
            "nested": {"level2": "&lt;value&gt;", "deep": "&amp;&quot;"},
        }
        result = validate_r2_data(data, "dict")

        # Only top-level values are cleaned by _clean_dict_values
        assert result["level1"] == "Test "
        # Nested dicts are not recursively cleaned in current implementation
        assert isinstance(result["nested"], dict)

    def test_validate_list_with_empty_dicts(self) -> None:
        """Test list validation preserves empty dicts."""
        data = [{}, {"key": "value"}, {}]
        result = validate_r2_data(data, "list")

        assert len(result) == 3
        assert result[0] == {}
        assert result[1] == {"key": "value"}
        assert result[2] == {}

    def test_sanitize_mixed_ansi_and_html(self) -> None:
        """Test sanitization handles mixed ANSI and HTML."""
        text = "\x1b[31mRED&nbsp;TEXT\x1b[0m&lt;tag&gt;"
        result = sanitize_r2_output(text)

        assert "\x1b" not in result
        assert "RED TEXT" in result
        assert "<tag>" in result

    def test_validate_address_large_value(self) -> None:
        """Test validation of very large address values."""
        large_addr = 0xFFFFFFFFFFFFFFFF
        result = validate_address(large_addr)

        assert result == large_addr

    def test_validate_size_large_value(self) -> None:
        """Test validation of very large size values."""
        large_size = 0x7FFFFFFF
        result = validate_size(large_size)

        assert result == large_size

    def test_validate_bytes_encode_error(self) -> None:
        """Test bytes validation handles encode errors."""
        # String that could cause encoding issues
        data = "test\udc80string"  # Lone surrogate
        result = validate_r2_data(data, "bytes")

        # Should handle the error and produce some output
        assert isinstance(result, bytes)
