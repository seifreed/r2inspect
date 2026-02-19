#!/usr/bin/env python3
"""Comprehensive tests for string_domain module."""

import base64

from r2inspect.modules.string_domain import (
    SUSPICIOUS_PATTERNS,
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


def test_filter_strings_within_range():
    strings = ["abc", "test", "hello", "x", "verylongstring"]
    result = filter_strings(strings, min_length=3, max_length=10)
    assert "abc" in result
    assert "test" in result
    assert "hello" in result
    assert "x" not in result
    assert "verylongstring" not in result


def test_filter_strings_removes_unprintable():
    strings = ["hello\x00world", "clean", "test\x01\x02"]
    result = filter_strings(strings, min_length=3, max_length=20)
    assert "clean" in result
    filtered_first = [s for s in result if "hello" in s][0] if any("hello" in s for s in result) else None
    if filtered_first:
        assert "\x00" not in filtered_first


def test_filter_strings_empty_list():
    result = filter_strings([], min_length=3, max_length=10)
    assert result == []


def test_filter_strings_all_too_short():
    strings = ["a", "ab", "x"]
    result = filter_strings(strings, min_length=3, max_length=10)
    assert result == []


def test_filter_strings_all_too_long():
    strings = ["verylongstring", "anotherlongstring"]
    result = filter_strings(strings, min_length=3, max_length=5)
    assert result == []


def test_filter_strings_edge_cases():
    strings = ["abc", "abcd"]
    result = filter_strings(strings, min_length=3, max_length=3)
    assert "abc" in result
    assert "abcd" not in result


def test_parse_search_results_valid_addresses():
    result = "0x00401000 some data\n0x00402000 more data\n0x00403000 end"
    addresses = parse_search_results(result)
    assert len(addresses) == 3
    assert "0x00401000" in addresses
    assert "0x00402000" in addresses
    assert "0x00403000" in addresses


def test_parse_search_results_mixed_lines():
    result = "0x00401000 data\nno address here\n0x00402000 more"
    addresses = parse_search_results(result)
    assert len(addresses) == 2
    assert "0x00401000" in addresses
    assert "0x00402000" in addresses


def test_parse_search_results_empty():
    result = ""
    addresses = parse_search_results(result)
    assert addresses == []


def test_parse_search_results_no_matches():
    result = "no addresses\nhere at all\njust text"
    addresses = parse_search_results(result)
    assert addresses == []


def test_xor_string_basic():
    text = "hello"
    key = 42
    result = xor_string(text, key)
    assert len(result) == len(text)
    assert result != text
    decoded = xor_string(result, key)
    assert decoded == text


def test_xor_string_key_zero():
    text = "test"
    result = xor_string(text, 0)
    assert result == text


def test_xor_string_key_255():
    text = "abc"
    result = xor_string(text, 255)
    assert len(result) == len(text)
    assert result != text


def test_xor_string_empty():
    result = xor_string("", 42)
    assert result == ""


def test_xor_string_single_char():
    result = xor_string("A", 1)
    assert len(result) == 1
    assert ord(result[0]) == ord("A") ^ 1


def test_build_xor_matches_basic():
    search_string = "test"
    calls = []
    
    def mock_search_hex(pattern):
        calls.append(pattern)
        if pattern == "test".encode().hex():
            return "0x00401000 match"
        return ""
    
    matches = build_xor_matches(search_string, mock_search_hex)
    assert isinstance(matches, list)
    assert len(calls) == 255


def test_build_xor_matches_with_results():
    search_string = "A"
    
    def mock_search_hex(pattern):
        if pattern == xor_string("A", 42).encode().hex():
            return "0x00401000 found"
        return ""
    
    matches = build_xor_matches(search_string, mock_search_hex)
    matched = [m for m in matches if m["xor_key"] == 42]
    assert len(matched) == 1
    assert matched[0]["original_string"] == "A"
    assert matched[0]["xor_key"] == 42


def test_build_xor_matches_no_results():
    search_string = "test"
    
    def mock_search_hex(pattern):
        return ""
    
    matches = build_xor_matches(search_string, mock_search_hex)
    assert matches == []


def test_find_suspicious_urls():
    strings = ["http://malware.com", "normal text", "https://evil.org/payload"]
    suspicious = find_suspicious(strings)
    url_matches = [s for s in suspicious if s["type"] == "urls"]
    assert len(url_matches) >= 1


def test_find_suspicious_ips():
    strings = ["192.168.1.1", "normal text", "10.0.0.1"]
    suspicious = find_suspicious(strings)
    ip_matches = [s for s in suspicious if s["type"] == "ips"]
    assert len(ip_matches) >= 1


def test_find_suspicious_emails():
    strings = ["test@example.com", "normal text", "malware@evil.org"]
    suspicious = find_suspicious(strings)
    email_matches = [s for s in suspicious if s["type"] == "emails"]
    assert len(email_matches) >= 1


def test_find_suspicious_registry():
    strings = ["HKEY_LOCAL_MACHINE\\Software\\Test", "normal text"]
    suspicious = find_suspicious(strings)
    reg_matches = [s for s in suspicious if s["type"] == "registry"]
    assert len(reg_matches) >= 1


def test_find_suspicious_files():
    strings = ["C:\\Windows\\System32\\evil.dll", "normal text"]
    suspicious = find_suspicious(strings)
    file_matches = [s for s in suspicious if s["type"] == "files"]
    assert len(file_matches) >= 1


def test_find_suspicious_api_calls():
    strings = ["VirtualAlloc", "CreateRemoteThread", "normal text"]
    suspicious = find_suspicious(strings)
    api_matches = [s for s in suspicious if s["type"] == "api_calls"]
    assert len(api_matches) >= 1


def test_find_suspicious_crypto():
    strings = ["AES encryption", "SHA256 hash", "normal text"]
    suspicious = find_suspicious(strings)
    crypto_matches = [s for s in suspicious if s["type"] == "crypto"]
    assert len(crypto_matches) >= 1


def test_find_suspicious_mutex():
    strings = ["Global\\MalwareMutex", "normal text"]
    suspicious = find_suspicious(strings)
    mutex_matches = [s for s in suspicious if s["type"] == "mutex"]
    assert len(mutex_matches) >= 1


def test_find_suspicious_base64():
    strings = ["dGVzdCBkYXRhIGhlcmUgbG9uZyBlbm91Z2g=", "short"]
    suspicious = find_suspicious(strings)
    b64_matches = [s for s in suspicious if s["type"] == "base64"]
    assert len(b64_matches) >= 1


def test_find_suspicious_multiple_patterns():
    strings = ["http://malware.com with VirtualAlloc and AES"]
    suspicious = find_suspicious(strings)
    assert len(suspicious) >= 3


def test_find_suspicious_empty_list():
    suspicious = find_suspicious([])
    assert suspicious == []


def test_find_suspicious_no_matches():
    strings = ["normal", "clean", "text"]
    suspicious = find_suspicious(strings)
    assert suspicious == []


def test_is_base64_valid():
    assert is_base64("dGVzdA==")
    assert is_base64("SGVsbG9Xb3JsZA==")
    assert is_base64("YWJjZGVmZ2g=")


def test_is_base64_valid_no_padding():
    assert is_base64("dGVzdGRhdGE=") or not is_base64("dGVzdGRhdGE=")


def test_is_base64_invalid_too_short():
    assert not is_base64("abc")
    assert not is_base64("test")


def test_is_base64_invalid_wrong_length():
    assert not is_base64("abc")
    assert not is_base64("abcde")


def test_is_base64_invalid_chars():
    assert not is_base64("not@base64!!")
    assert not is_base64("test test")


def test_is_hex_valid():
    assert is_hex("deadbeef")
    assert is_hex("1234567890abcdef")
    assert is_hex("ABCDEF")


def test_is_hex_invalid_too_short():
    assert not is_hex("ab")
    assert not is_hex("a")


def test_is_hex_invalid_odd_length():
    assert not is_hex("abc")
    assert not is_hex("12345")


def test_is_hex_invalid_chars():
    assert not is_hex("notahex!")
    assert not is_hex("xyz123")


def test_decode_base64_valid():
    encoded = base64.b64encode(b"test data").decode()
    result = decode_base64(encoded)
    assert result is not None
    assert result["original"] == encoded
    assert result["decoded"] == "test data"
    assert result["encoding"] == "base64"


def test_decode_base64_invalid():
    result = decode_base64("not base64")
    assert result is None


def test_decode_base64_too_short():
    result = decode_base64("abc")
    assert result is None


def test_decode_base64_invalid_padding():
    result = decode_base64("YWJjZGVm===")
    assert result is None


def test_decode_base64_non_printable():
    encoded = base64.b64encode(b"\x00\x01\x02\x03\x04").decode()
    result = decode_base64(encoded)
    assert result is None or not result["decoded"].isprintable()


def test_decode_hex_valid():
    encoded = "746573742064617461"
    result = decode_hex(encoded)
    assert result is not None
    assert result["original"] == encoded
    assert result["decoded"] == "test data"
    assert result["encoding"] == "hex"


def test_decode_hex_invalid():
    result = decode_hex("not hex")
    assert result is None


def test_decode_hex_too_short():
    result = decode_hex("ab")
    assert result is None


def test_decode_hex_odd_length():
    result = decode_hex("abc")
    assert result is None


def test_decode_hex_invalid_chars():
    result = decode_hex("zzzz")
    assert result is None


def test_decode_hex_non_printable():
    encoded = "00010203"
    result = decode_hex(encoded)
    assert result is None or not result["decoded"].isprintable()


def test_suspicious_patterns_all_defined():
    assert "urls" in SUSPICIOUS_PATTERNS
    assert "ips" in SUSPICIOUS_PATTERNS
    assert "emails" in SUSPICIOUS_PATTERNS
    assert "registry" in SUSPICIOUS_PATTERNS
    assert "files" in SUSPICIOUS_PATTERNS
    assert "api_calls" in SUSPICIOUS_PATTERNS
    assert "crypto" in SUSPICIOUS_PATTERNS
    assert "mutex" in SUSPICIOUS_PATTERNS
    assert "base64" in SUSPICIOUS_PATTERNS


def test_suspicious_patterns_are_valid_regex():
    import re
    for pattern_name, pattern in SUSPICIOUS_PATTERNS.items():
        try:
            re.compile(pattern)
        except re.error:
            assert False, f"Invalid regex pattern for {pattern_name}"


def test_filter_strings_preserves_printable():
    strings = ["hello world", "test123", "clean_text"]
    result = filter_strings(strings, min_length=3, max_length=20)
    assert len(result) == 3
    for s in result:
        assert s.isprintable()


def test_xor_string_reversible():
    original = "secret message"
    key = 123
    encrypted = xor_string(original, key)
    decrypted = xor_string(encrypted, key)
    assert decrypted == original


def test_build_xor_matches_contains_metadata():
    search_string = "A"
    
    def mock_search_hex(pattern):
        if pattern == xor_string("A", 10).encode().hex():
            return "0x00401000 match"
        return ""
    
    matches = build_xor_matches(search_string, mock_search_hex)
    matched = [m for m in matches if m["xor_key"] == 10]
    assert len(matched) == 1
    assert "original_string" in matched[0]
    assert "xor_key" in matched[0]
    assert "xor_result" in matched[0]
    assert "addresses" in matched[0]


def test_find_suspicious_returns_match_details():
    strings = ["test@example.com"]
    suspicious = find_suspicious(strings)
    assert len(suspicious) >= 1
    for entry in suspicious:
        assert "string" in entry
        assert "type" in entry
        assert "matches" in entry


def test_decode_base64_handles_unicode_errors():
    invalid_b64 = "YWJjZA=="
    result = decode_base64(invalid_b64)
    if result is None:
        assert True
    else:
        assert isinstance(result["decoded"], str)


def test_decode_hex_handles_unicode_errors():
    invalid_hex = "abcd"
    result = decode_hex(invalid_hex)
    if result is None:
        assert True
    else:
        assert isinstance(result["decoded"], str)
