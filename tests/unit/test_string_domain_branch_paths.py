#!/usr/bin/env python3
"""Branch path tests for r2inspect/modules/string_domain.py covering missing lines."""

from __future__ import annotations

import base64

import pytest

from r2inspect.modules.string_domain import (
    build_xor_matches,
    decode_base64,
    decode_hex,
    filter_strings,
    find_suspicious,
    is_base64,
    is_hex,
    parse_search_results,
    xor_string,
)


# ---------------------------------------------------------------------------
# xor_string() - line 46
# ---------------------------------------------------------------------------


def test_xor_string_produces_output_for_printable_chars():
    """xor_string applies XOR to each character and returns string (line 46)."""
    result = xor_string("hello", 0x41)
    assert len(result) == 5
    assert result != "hello"


def test_xor_string_is_reversible():
    """xor_string applied twice with same key restores original."""
    original = "secret"
    key = 0x55
    assert xor_string(xor_string(original, key), key) == original


def test_xor_string_key_one():
    """xor_string with key=1 shifts each char by 1."""
    result = xor_string("A", 1)
    assert ord(result) == ord("A") ^ 1


# ---------------------------------------------------------------------------
# build_xor_matches() - lines 52-58, 66
# ---------------------------------------------------------------------------


def test_build_xor_matches_returns_empty_when_no_hits():
    """build_xor_matches returns empty list when search_hex never matches (lines 52-66)."""

    def search_hex(pattern: str) -> str:
        return ""

    matches = build_xor_matches("data", search_hex)
    assert matches == []


def test_build_xor_matches_finds_hit_at_correct_key():
    """build_xor_matches appends match dict when search_hex returns results (lines 57-64)."""
    target_key = 17

    def search_hex(pattern: str) -> str:
        if pattern == xor_string("test", target_key).encode().hex():
            return "0x00401000 found\n"
        return ""

    matches = build_xor_matches("test", search_hex)
    assert len(matches) == 1
    assert matches[0]["xor_key"] == target_key
    assert matches[0]["original_string"] == "test"
    assert "xor_result" in matches[0]
    assert "addresses" in matches[0]


def test_build_xor_matches_iterates_all_255_keys():
    """build_xor_matches calls search_hex 255 times (keys 1-255) (line 53)."""
    call_count = []

    def search_hex(pattern: str) -> str:
        call_count.append(pattern)
        return ""

    build_xor_matches("x", search_hex)
    assert len(call_count) == 255


def test_build_xor_matches_address_parsing():
    """build_xor_matches parses 0x addresses from search result (line 63)."""

    def search_hex(pattern: str) -> str:
        if pattern == xor_string("A", 42).encode().hex():
            return "0x00401000 data\n0x00402000 data\n"
        return ""

    matches = build_xor_matches("A", search_hex)
    assert len(matches) == 1
    assert "0x00401000" in matches[0]["addresses"]
    assert "0x00402000" in matches[0]["addresses"]


# ---------------------------------------------------------------------------
# find_suspicious() - lines 75, 80-89
# ---------------------------------------------------------------------------


def test_find_suspicious_appends_each_matching_pattern():
    """find_suspicious appends dict entry for each pattern match (line 75)."""
    strings = ["http://malware.example.com/payload"]
    result = find_suspicious(strings)
    url_entries = [r for r in result if r["type"] == "urls"]
    assert len(url_entries) >= 1
    assert url_entries[0]["string"] == strings[0]
    assert "matches" in url_entries[0]


def test_find_suspicious_multiple_patterns_in_one_string():
    """find_suspicious detects multiple pattern types in a single string (lines 69-76)."""
    strings = ["VirtualAlloc http://evil.org AES 192.168.1.1"]
    result = find_suspicious(strings)
    pattern_types = {r["type"] for r in result}
    assert "api_calls" in pattern_types
    assert "urls" in pattern_types


def test_find_suspicious_empty_returns_empty_list():
    """find_suspicious returns empty list for empty input (line 70)."""
    result = find_suspicious([])
    assert result == []


def test_find_suspicious_no_pattern_match_returns_empty():
    """find_suspicious returns empty list when no patterns match (lines 69-76)."""
    result = find_suspicious(["nothing suspicious here at all"])
    assert result == []


# ---------------------------------------------------------------------------
# decode_base64() - lines 80-89
# ---------------------------------------------------------------------------


def test_decode_base64_valid_utf8_printable_string():
    """decode_base64 decodes valid base64 of printable UTF-8 string (lines 82-86)."""
    plaintext = "hello world!"
    encoded = base64.b64encode(plaintext.encode()).decode()
    result = decode_base64(encoded)
    assert result is not None
    assert result["original"] == encoded
    assert result["decoded"] == plaintext
    assert result["encoding"] == "base64"


def test_decode_base64_returns_none_for_non_printable_decoded():
    """decode_base64 returns None when decoded bytes are not printable (lines 84-86 false path)."""
    raw = bytes([0, 1, 2, 3, 4, 5, 6, 7, 8])
    encoded = base64.b64encode(raw).decode()
    result = decode_base64(encoded)
    assert result is None


def test_decode_base64_returns_none_for_invalid_base64():
    """decode_base64 returns None when is_base64() check fails (line 81)."""
    result = decode_base64("not_base64!!!")
    assert result is None


def test_decode_base64_returns_none_for_too_short():
    """decode_base64 returns None for string shorter than 8 chars (line 81)."""
    result = decode_base64("abc")
    assert result is None


# ---------------------------------------------------------------------------
# decode_hex() - lines 93-102
# ---------------------------------------------------------------------------


def test_decode_hex_valid_printable_string():
    """decode_hex decodes valid hex of printable string (lines 95-99)."""
    plaintext = "hello"
    hex_encoded = plaintext.encode().hex()
    result = decode_hex(hex_encoded)
    assert result is not None
    assert result["original"] == hex_encoded
    assert result["decoded"] == "hello"
    assert result["encoding"] == "hex"


def test_decode_hex_returns_none_for_non_printable():
    """decode_hex returns None when decoded string is not printable (lines 97-99 false path)."""
    raw = bytes([0x00, 0x01, 0x02, 0x03])
    hex_str = raw.hex()
    result = decode_hex(hex_str)
    assert result is None


def test_decode_hex_returns_none_for_invalid_hex():
    """decode_hex returns None when is_hex() check fails (line 94)."""
    result = decode_hex("xyz!")
    assert result is None


def test_decode_hex_returns_none_for_too_short():
    """decode_hex returns None for string shorter than 4 chars (line 94)."""
    result = decode_hex("ab")
    assert result is None


def test_decode_hex_returns_none_for_odd_length():
    """decode_hex returns None for odd-length string (line 94)."""
    result = decode_hex("abc")
    assert result is None


# ---------------------------------------------------------------------------
# is_base64() - lines 106-108
# ---------------------------------------------------------------------------


def test_is_base64_valid_padded():
    """is_base64 returns True for valid base64 with padding (lines 106-108)."""
    assert is_base64("dGVzdA==") is True


def test_is_base64_valid_without_padding():
    """is_base64 returns True for valid 8-char no-padding base64."""
    assert is_base64("dGVzdGRh") is True


def test_is_base64_false_for_short_string():
    """is_base64 returns False when length < 8 (line 106)."""
    assert is_base64("abc") is False
    assert is_base64("abcdefg") is False


def test_is_base64_false_for_non_multiple_of_4():
    """is_base64 returns False when length is not multiple of 4 (line 107)."""
    assert is_base64("abcdefghij") is False


def test_is_base64_false_for_invalid_chars():
    """is_base64 returns False for strings with non-base64 characters (line 108)."""
    assert is_base64("!@#$%^&*") is False


# ---------------------------------------------------------------------------
# is_hex() - lines 112-114
# ---------------------------------------------------------------------------


def test_is_hex_valid_lowercase():
    """is_hex returns True for valid lowercase hex string (lines 112-114)."""
    assert is_hex("deadbeef") is True


def test_is_hex_valid_uppercase():
    """is_hex returns True for valid uppercase hex string."""
    assert is_hex("DEADBEEF") is True


def test_is_hex_false_for_short_string():
    """is_hex returns False when length < 4 (line 112)."""
    assert is_hex("ab") is False


def test_is_hex_false_for_odd_length():
    """is_hex returns False for odd-length string (line 113)."""
    assert is_hex("abc") is False
    assert is_hex("12345") is False


def test_is_hex_false_for_non_hex_chars():
    """is_hex returns False for strings with non-hex chars (line 114)."""
    assert is_hex("gggg") is False
    assert is_hex("xyz0") is False
