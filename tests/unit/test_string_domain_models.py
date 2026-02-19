#!/usr/bin/env python3
"""Tests for string_domain module."""

import pytest
from r2inspect.modules.string_domain import (
    filter_strings,
    parse_search_results,
    xor_string,
    build_xor_matches,
    find_suspicious,
    decode_base64,
    decode_hex,
    is_base64,
    is_hex,
)


class TestFilterStrings:
    """Tests for filter_strings function."""

    def test_filter_strings_empty_list(self):
        """Test filtering empty string list."""
        result = filter_strings([], 4, 20)
        assert result == []

    def test_filter_strings_basic(self):
        """Test basic string filtering with min/max length."""
        strings = ["hi", "test", "verylongstring", "ok"]
        result = filter_strings(strings, 4, 10)
        assert "test" in result
        assert "hi" not in result
        assert "verylongstring" not in result

    def test_filter_strings_with_nonprintable(self):
        """Test filtering removes non-printable characters."""
        strings = ["test\x00string", "normal", "good"]
        result = filter_strings(strings, 4, 20)
        assert "teststring" in result
        assert "normal" in result

    def test_filter_strings_exact_length(self):
        """Test strings at exact min/max boundaries."""
        strings = ["1234", "12345", "123456789", "1234567890"]
        result = filter_strings(strings, 5, 9)
        assert "12345" in result
        assert "123456789" in result
        assert "1234" not in result
        assert "1234567890" not in result

    def test_filter_strings_all_too_short(self):
        """Test when all strings are too short."""
        strings = ["a", "bb", "ccc"]
        result = filter_strings(strings, 10, 20)
        assert result == []

    def test_filter_strings_all_too_long(self):
        """Test when all strings are too long."""
        strings = ["verylongstringhere", "anotherlongstring"]
        result = filter_strings(strings, 1, 5)
        assert result == []

    def test_filter_strings_becomes_short_after_cleaning(self):
        """Test string that becomes too short after removing non-printable."""
        strings = ["ab\x00\x01\x02cd"]
        result = filter_strings(strings, 10, 20)
        assert "abcd" not in result


class TestParseSearchResults:
    """Tests for parse_search_results function."""

    def test_parse_search_results_empty(self):
        """Test parsing empty result string."""
        result = parse_search_results("")
        assert result == []

    def test_parse_search_results_single_address(self):
        """Test parsing single address."""
        result = parse_search_results("0x1000 10 some data")
        assert "0x1000" in result

    def test_parse_search_results_multiple_addresses(self):
        """Test parsing multiple addresses."""
        input_str = "0x1000 10 data\n0x2000 20 more\n0x3000 30 stuff"
        result = parse_search_results(input_str)
        assert len(result) == 3
        assert "0x1000" in result
        assert "0x2000" in result
        assert "0x3000" in result

    def test_parse_search_results_non_address_lines(self):
        """Test that non-address lines are ignored."""
        input_str = "0x1000 10 data\nno address here\n0x2000 20 more"
        result = parse_search_results(input_str)
        assert len(result) == 2
        assert "0x1000" in result
        assert "0x2000" in result

    def test_parse_search_results_whitespace_handling(self):
        """Test handling of whitespace."""
        input_str = "  0x1000 10 data  \n  0x2000 20 more  "
        result = parse_search_results(input_str)
        assert len(result) == 2


class TestXorString:
    """Tests for xor_string function."""

    def test_xor_string_basic(self):
        """Test basic XOR operation."""
        original = "hello"
        key = 42
        xored = xor_string(original, key)
        assert len(xored) == len(original)
        assert xored != original

    def test_xor_string_reversible(self):
        """Test that XOR can be reversed with same key."""
        original = "test"
        key = 99
        xored = xor_string(original, key)
        reversed_back = xor_string(xored, key)
        assert reversed_back == original

    def test_xor_string_different_keys(self):
        """Test same string with different keys produces different results."""
        original = "hello"
        xored1 = xor_string(original, 10)
        xored2 = xor_string(original, 20)
        assert xored1 != xored2

    def test_xor_string_with_special_characters(self):
        """Test XOR with special characters."""
        original = "!@#$%^&*()"
        key = 123
        xored = xor_string(original, key)
        assert len(xored) == len(original)
        reversed_back = xor_string(xored, key)
        assert reversed_back == original

    def test_xor_string_empty(self):
        """Test XOR with empty string."""
        result = xor_string("", 42)
        assert result == ""


class TestBuildXorMatches:
    """Tests for build_xor_matches function."""

    def test_build_xor_matches_no_results(self):
        """Test when no matches are found."""
        def mock_search(pattern):
            return ""

        result = build_xor_matches("test", mock_search)
        assert result == []

    def test_build_xor_matches_with_results(self):
        """Test when matches are found."""
        def mock_search(pattern):
            if "0x" in pattern or len(pattern) > 10:
                return "0x1000 some data\n0x2000 more data"
            return ""

        result = build_xor_matches("a", mock_search)
        assert len(result) > 0
        assert all("xor_key" in match for match in result)
        assert all("addresses" in match for match in result)

    def test_build_xor_matches_structure(self):
        """Test structure of returned matches."""
        def mock_search(pattern):
            return "0x1000 data"

        result = build_xor_matches("test", mock_search)
        if result:
            match = result[0]
            assert "original_string" in match
            assert "xor_key" in match
            assert "xor_result" in match
            assert "addresses" in match
            assert match["original_string"] == "test"


class TestFindSuspicious:
    """Tests for find_suspicious function."""

    def test_find_suspicious_empty_list(self):
        """Test with empty string list."""
        result = find_suspicious([])
        assert result == []

    def test_find_suspicious_url(self):
        """Test detection of URLs."""
        strings = ["http://example.com/malware", "normal string"]
        result = find_suspicious(strings)
        assert len(result) > 0
        assert any("url" in r["type"] for r in result)

    def test_find_suspicious_ip(self):
        """Test detection of IP addresses."""
        strings = ["192.168.1.1", "10.0.0.1"]
        result = find_suspicious(strings)
        assert len(result) > 0
        assert any("ip" in r["type"] for r in result)

    def test_find_suspicious_email(self):
        """Test detection of email addresses."""
        strings = ["admin@malware.com", "test@example.org"]
        result = find_suspicious(strings)
        assert len(result) > 0
        assert any("email" in r["type"] for r in result)

    def test_find_suspicious_registry(self):
        """Test detection of registry paths."""
        strings = ["HKEY_LOCAL_MACHINE\\Software\\Windows"]
        result = find_suspicious(strings)
        assert len(result) > 0

    def test_find_suspicious_api_calls(self):
        """Test detection of API calls."""
        strings = ["VirtualAlloc", "CreateRemoteThread"]
        result = find_suspicious(strings)
        assert len(result) > 0

    def test_find_suspicious_crypto(self):
        """Test detection of crypto algorithms."""
        strings = ["AES-256", "RSA", "MD5"]
        result = find_suspicious(strings)
        assert len(result) > 0

    def test_find_suspicious_mutex(self):
        """Test detection of mutex patterns."""
        strings = ["Global\\MutexName", "Local\\SomeMutex"]
        result = find_suspicious(strings)
        assert len(result) > 0

    def test_find_suspicious_base64(self):
        """Test detection of base64 strings."""
        strings = ["aGVsbG8gd29ybGQ=", "dGVzdCBzdHJpbmc="]
        result = find_suspicious(strings)
        assert len(result) > 0

    def test_find_suspicious_multiple_patterns(self):
        """Test string with multiple suspicious patterns."""
        strings = ["http://malware.com admin@malware.com 192.168.1.1"]
        result = find_suspicious(strings)
        assert len(result) > 0


class TestDecodeBase64:
    """Tests for decode_base64 function."""

    def test_decode_base64_valid(self):
        """Test decoding valid base64 string."""
        encoded = "aGVsbG8="
        result = decode_base64(encoded)
        assert result is not None
        assert result["original"] == encoded
        assert "hello" in result["decoded"]

    def test_decode_base64_invalid_too_short(self):
        """Test that short strings return None."""
        result = decode_base64("ab")
        assert result is None

    def test_decode_base64_invalid_not_base64(self):
        """Test invalid base64 characters."""
        result = decode_base64("!!!!!!!!!!")
        assert result is None

    def test_decode_base64_not_multiple_of_4(self):
        """Test string not multiple of 4 length."""
        result = decode_base64("abc")
        assert result is None

    def test_decode_base64_correct_encoding_field(self):
        """Test that encoding field is set correctly."""
        encoded = "dGVzdA=="
        result = decode_base64(encoded)
        if result:
            assert result["encoding"] == "base64"

    def test_decode_base64_unprintable(self):
        """Test base64 that decodes to unprintable characters."""
        encoded = "\x00\x01\x02\x03"
        result = decode_base64(encoded)
        assert result is None


class TestDecodeHex:
    """Tests for decode_hex function."""

    def test_decode_hex_valid(self):
        """Test decoding valid hex string."""
        hex_str = "68656c6c6f"
        result = decode_hex(hex_str)
        assert result is not None
        assert result["original"] == hex_str
        assert "hello" in result["decoded"]

    def test_decode_hex_uppercase(self):
        """Test hex with uppercase letters."""
        hex_str = "68656C6C6F"
        result = decode_hex(hex_str)
        assert result is not None

    def test_decode_hex_invalid_too_short(self):
        """Test that short strings return None."""
        result = decode_hex("ab")
        assert result is None

    def test_decode_hex_invalid_characters(self):
        """Test hex with invalid characters."""
        result = decode_hex("gghhiijj")
        assert result is None

    def test_decode_hex_odd_length(self):
        """Test odd-length hex string."""
        result = decode_hex("12345")
        assert result is None

    def test_decode_hex_correct_encoding_field(self):
        """Test that encoding field is set correctly."""
        hex_str = "74657374"
        result = decode_hex(hex_str)
        if result:
            assert result["encoding"] == "hex"


class TestIsBase64:
    """Tests for is_base64 function."""

    def test_is_base64_valid_with_padding(self):
        """Test valid base64 with padding."""
        assert is_base64("aGVsbG8=") is True

    def test_is_base64_valid_without_padding(self):
        """Test valid base64 without padding."""
        assert is_base64("aGVsbG8") is True

    def test_is_base64_valid_long(self):
        """Test valid longer base64."""
        assert is_base64("dGhpcyBpcyBhIHRlc3Q=") is True

    def test_is_base64_too_short(self):
        """Test string too short."""
        assert is_base64("ab") is False

    def test_is_base64_invalid_characters(self):
        """Test invalid base64 characters."""
        assert is_base64("!!!!!!!!!!!!") is False

    def test_is_base64_not_multiple_of_4(self):
        """Test length not multiple of 4."""
        assert is_base64("abc") is False

    def test_is_base64_with_special_chars(self):
        """Test base64 can include + and / and -."""
        assert is_base64("ab+/cd==") is True

    def test_is_base64_empty(self):
        """Test empty string."""
        assert is_base64("") is False


class TestIsHex:
    """Tests for is_hex function."""

    def test_is_hex_valid_lowercase(self):
        """Test valid hex with lowercase."""
        assert is_hex("68656c6c6f") is True

    def test_is_hex_valid_uppercase(self):
        """Test valid hex with uppercase."""
        assert is_hex("68656C6C6F") is True

    def test_is_hex_valid_mixed(self):
        """Test valid hex with mixed case."""
        assert is_hex("68656C6c6F") is True

    def test_is_hex_too_short(self):
        """Test string too short."""
        assert is_hex("ab") is False

    def test_is_hex_invalid_characters(self):
        """Test invalid hex characters."""
        assert is_hex("gghhiijj") is False

    def test_is_hex_odd_length(self):
        """Test odd-length hex."""
        assert is_hex("12345") is False

    def test_is_hex_with_spaces(self):
        """Test hex with spaces."""
        assert is_hex("12 34 56") is False

    def test_is_hex_empty(self):
        """Test empty string."""
        assert is_hex("") is False

    def test_is_hex_minimum_valid_length(self):
        """Test minimum valid length (4 chars, 2 bytes)."""
        assert is_hex("1234") is True
