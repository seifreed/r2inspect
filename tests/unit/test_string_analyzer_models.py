#!/usr/bin/env python3
"""Tests for string_analyzer module.

Rewritten to use real objects (FakeR2 + R2PipeAdapter + real Config) instead of mocks.
"""

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.modules.string_analyzer import StringAnalyzer
from r2inspect.domain.formats.string import (
    build_xor_matches,
    decode_base64,
    decode_hex,
    filter_strings,
    find_suspicious,
    is_base64,
    is_hex,
    xor_string,
)
from r2inspect.modules.string_extraction import extract_strings_from_entries
from r2inspect.testing.fake_r2 import FakeR2


# ---------------------------------------------------------------------------
# FakeR2 – lightweight stand-in for an r2pipe handle
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(tmp_path, **overrides):
    """Build a real Config with optional overrides for strings/general."""
    import json
    import copy

    config_dict = copy.deepcopy(Config.DEFAULT_CONFIG)
    for key, val in overrides.get("strings", {}).items():
        config_dict["strings"][key] = val
    for key, val in overrides.get("general", {}).items():
        config_dict["general"][key] = val
    config_path = str(tmp_path / "r2inspect_string_test.json")
    with open(config_path, "w") as f:
        json.dump(config_dict, f)
    return Config(config_path)


def _make_analyzer(tmp_path, cmdj_map=None, cmd_map=None, **config_overrides):
    """Build a StringAnalyzer backed by FakeR2 through a real R2PipeAdapter."""
    fake = FakeR2(cmdj_map=cmdj_map or {}, cmd_map=cmd_map or {})
    adapter = R2PipeAdapter(fake)
    cfg = _make_config(tmp_path, **config_overrides)
    return StringAnalyzer(adapter, cfg)


# ---------------------------------------------------------------------------
# TestStringAnalyzerInit
# ---------------------------------------------------------------------------


class TestStringAnalyzerInit:
    """Tests for StringAnalyzer initialization."""

    def test_string_analyzer_init_valid(self, tmp_path):
        """Test StringAnalyzer initialization with valid config."""
        analyzer = _make_analyzer(tmp_path)
        assert analyzer is not None
        assert analyzer.min_length == 4
        assert analyzer.max_length == 100
        assert analyzer.max_strings == 1000

    def test_string_analyzer_init_stores_config(self, tmp_path):
        """Test that init stores adapter and config."""
        fake = FakeR2()
        adapter = R2PipeAdapter(fake)
        cfg = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, cfg)
        assert analyzer.adapter is adapter
        assert analyzer.config is cfg


# ---------------------------------------------------------------------------
# TestStringAnalyzerCategory
# ---------------------------------------------------------------------------


class TestStringAnalyzerCategory:
    """Tests for get_category method."""

    def test_get_category(self, tmp_path):
        """Test that category is metadata."""
        analyzer = _make_analyzer(tmp_path)
        assert analyzer.get_category() == "metadata"


# ---------------------------------------------------------------------------
# TestStringAnalyzerDescription
# ---------------------------------------------------------------------------


class TestStringAnalyzerDescription:
    """Tests for get_description method."""

    def test_get_description(self, tmp_path):
        """Test that description mentions string analysis."""
        analyzer = _make_analyzer(tmp_path)
        desc = analyzer.get_description()
        assert "string" in desc.lower()
        assert "extract" in desc.lower()


# ---------------------------------------------------------------------------
# TestExtractStrings
# ---------------------------------------------------------------------------


class TestExtractStrings:
    """Tests for extract_strings method."""

    def test_extract_strings_empty(self, tmp_path):
        """Test extracting strings when none are found."""
        analyzer = _make_analyzer(
            tmp_path,
            cmdj_map={"izj": [], "izuj": []},
        )
        result = analyzer.extract_strings()
        assert isinstance(result, list)
        assert result == []

    def test_extract_strings_filters_duplicates(self, tmp_path):
        """Test that duplicates are removed."""
        entries = [
            {"string": "test_string", "vaddr": 0x1000, "size": 11},
            {"string": "test_string", "vaddr": 0x2000, "size": 11},
            {"string": "other_str", "vaddr": 0x3000, "size": 9},
        ]
        analyzer = _make_analyzer(
            tmp_path,
            cmdj_map={"izj": entries, "izuj": entries[:1]},
        )
        result = analyzer.extract_strings()
        # Duplicates removed by set()
        assert result.count("test_string") == 1

    def test_extract_strings_respects_max_strings(self, tmp_path):
        """Test that max_strings limit is respected."""
        entries = [{"string": f"string_{i:04d}", "vaddr": i * 0x100, "size": 11} for i in range(10)]
        analyzer = _make_analyzer(
            tmp_path,
            cmdj_map={"izj": entries, "izuj": []},
            strings={"min_length": 1},
            general={"max_strings": 3},
        )
        result = analyzer.extract_strings()
        assert len(result) <= 3

    def test_extract_strings_handles_exception(self, tmp_path):
        """Test exception handling in extract_strings when r2 raises."""
        # Providing an exception-raising FakeR2 for izj
        analyzer = _make_analyzer(
            tmp_path,
            cmdj_map={"izj": RuntimeError("Test error"), "izuj": []},
        )
        result = analyzer.extract_strings()
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# TestExtractAsciiStrings
# ---------------------------------------------------------------------------


class TestExtractAsciiStrings:
    """Tests for _extract_ascii_strings method."""

    def test_extract_ascii_strings_success(self, tmp_path):
        """Test successful ASCII string extraction."""
        entries = [
            {"string": "hello_world", "vaddr": 0x1000, "size": 11},
            {"string": "test_data", "vaddr": 0x2000, "size": 9},
        ]
        analyzer = _make_analyzer(tmp_path, cmdj_map={"izj": entries})
        result = analyzer._extract_ascii_strings()
        assert isinstance(result, list)
        assert "hello_world" in result
        assert "test_data" in result

    def test_extract_ascii_strings_exception(self, tmp_path):
        """Test exception handling in ASCII extraction."""
        analyzer = _make_analyzer(
            tmp_path,
            cmdj_map={"izj": RuntimeError("Test error")},
        )
        result = analyzer._extract_ascii_strings()
        assert result == []


# ---------------------------------------------------------------------------
# TestExtractUnicodeStrings
# ---------------------------------------------------------------------------


class TestExtractUnicodeStrings:
    """Tests for _extract_unicode_strings method."""

    def test_extract_unicode_strings_success(self, tmp_path):
        """Test successful Unicode string extraction."""
        entries = [
            {"string": "unicode_test", "vaddr": 0x5000, "size": 12},
        ]
        analyzer = _make_analyzer(tmp_path, cmdj_map={"izuj": entries})
        result = analyzer._extract_unicode_strings()
        assert isinstance(result, list)
        assert "unicode_test" in result

    def test_extract_unicode_strings_exception(self, tmp_path):
        """Test exception handling in Unicode extraction."""
        analyzer = _make_analyzer(
            tmp_path,
            cmdj_map={"izuj": RuntimeError("Test error")},
        )
        result = analyzer._extract_unicode_strings()
        assert result == []


# ---------------------------------------------------------------------------
# TestSearchXor – uses real domain function directly
# ---------------------------------------------------------------------------


class TestSearchXor:
    """Tests for XOR string search via domain helper."""

    def test_build_xor_matches_finds_match(self):
        """Test build_xor_matches with a search function that reports a hit."""
        target = "test"
        xored = xor_string(target, 42)
        hex_pattern = xored.encode().hex()

        def fake_search(pattern):
            if pattern == hex_pattern:
                return "0x00401000 hit0_0\n"
            return ""

        result = build_xor_matches(target, fake_search)
        assert isinstance(result, list)
        assert any(m["xor_key"] == 42 for m in result)

    def test_build_xor_matches_no_matches(self):
        """Test build_xor_matches when search finds nothing."""
        result = build_xor_matches("test", lambda _pattern: "")
        assert result == []


# ---------------------------------------------------------------------------
# TestGetSuspiciousStrings
# ---------------------------------------------------------------------------


class TestGetSuspiciousStrings:
    """Tests for get_suspicious_strings method."""

    def test_get_suspicious_strings_empty(self, tmp_path):
        """Test getting suspicious strings from empty list."""
        analyzer = _make_analyzer(tmp_path, cmdj_map={"izj": [], "izuj": []})
        result = analyzer.get_suspicious_strings()
        assert isinstance(result, list)
        assert result == []

    def test_get_suspicious_strings_with_url(self, tmp_path):
        """Test detection of suspicious URLs."""
        entries = [
            {"string": "http://malware.com/payload", "vaddr": 0x1000, "size": 27},
        ]
        analyzer = _make_analyzer(
            tmp_path,
            cmdj_map={"izj": entries, "izuj": []},
        )
        result = analyzer.get_suspicious_strings()
        assert isinstance(result, list)
        assert any(s["type"] == "urls" for s in result)

    def test_find_suspicious_domain_function(self):
        """Test find_suspicious directly with various suspicious patterns."""
        strings = [
            "http://evil.com",
            "192.168.1.1",
            "user@example.com",
            "VirtualAlloc",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Test",
        ]
        result = find_suspicious(strings)
        assert len(result) > 0
        types_found = {s["type"] for s in result}
        assert "urls" in types_found
        assert "ips" in types_found
        assert "api_calls" in types_found


# ---------------------------------------------------------------------------
# TestDecodeStrings
# ---------------------------------------------------------------------------


class TestDecodeStrings:
    """Tests for decode_strings method."""

    def test_decode_strings_empty(self, tmp_path):
        """Test decoding when no strings found."""
        analyzer = _make_analyzer(tmp_path, cmdj_map={"izj": [], "izuj": []})
        result = analyzer.decode_strings()
        assert result == []

    def test_decode_strings_with_base64(self, tmp_path):
        """Test decoding base64 strings from extracted data."""
        # "aGVsbG8gd29ybGQ=" decodes to "hello world"
        entries = [
            {"string": "aGVsbG8gd29ybGQ=", "vaddr": 0x1000, "size": 16},
        ]
        analyzer = _make_analyzer(
            tmp_path,
            cmdj_map={"izj": entries, "izuj": []},
            strings={"min_length": 4},
        )
        result = analyzer.decode_strings()
        assert isinstance(result, list)
        base64_decoded = [d for d in result if d.get("encoding") == "base64"]
        assert len(base64_decoded) >= 1
        assert base64_decoded[0]["decoded"] == "hello world"

    def test_decode_strings_with_hex(self, tmp_path):
        """Test decoding hex strings from extracted data."""
        # "68656c6c6f" is hex for "hello"
        entries = [
            {"string": "68656c6c6f", "vaddr": 0x2000, "size": 10},
        ]
        analyzer = _make_analyzer(
            tmp_path,
            cmdj_map={"izj": entries, "izuj": []},
            strings={"min_length": 4},
        )
        result = analyzer.decode_strings()
        assert isinstance(result, list)
        hex_decoded = [d for d in result if d.get("encoding") == "hex"]
        assert len(hex_decoded) >= 1
        assert hex_decoded[0]["decoded"] == "hello"


# ---------------------------------------------------------------------------
# TestDecodeBase64Method
# ---------------------------------------------------------------------------


class TestDecodeBase64Method:
    """Tests for _decode_base64 wrapper and domain function."""

    def test_decode_base64_method(self, tmp_path):
        """Test _decode_base64 wrapper method with valid input."""
        analyzer = _make_analyzer(tmp_path)
        result = analyzer._decode_base64("aGVsbG8gd29ybGQ=")
        assert result is not None
        assert result["decoded"] == "hello world"
        assert result["encoding"] == "base64"

    def test_decode_base64_invalid(self):
        """Test decode_base64 domain function with non-base64 input."""
        result = decode_base64("not-base64!")
        assert result is None

    def test_is_base64_valid(self):
        """Test is_base64 with valid base64."""
        assert is_base64("aGVsbG8gd29ybGQ=") is True

    def test_is_base64_too_short(self):
        """Test is_base64 rejects short strings."""
        assert is_base64("aGVs") is False


# ---------------------------------------------------------------------------
# TestDecodeHexMethod
# ---------------------------------------------------------------------------


class TestDecodeHexMethod:
    """Tests for _decode_hex wrapper and domain function."""

    def test_decode_hex_method(self, tmp_path):
        """Test _decode_hex wrapper method with valid input."""
        analyzer = _make_analyzer(tmp_path)
        result = analyzer._decode_hex("68656c6c6f")
        assert result is not None
        assert result["decoded"] == "hello"
        assert result["encoding"] == "hex"

    def test_decode_hex_invalid(self):
        """Test decode_hex domain function with non-hex input."""
        result = decode_hex("not-hex-at-all!")
        assert result is None

    def test_is_hex_valid(self):
        """Test is_hex with valid hex."""
        assert is_hex("68656c6c6f") is True  # 10 hex chars, even length
        assert is_hex("68656c6c") is True

    def test_is_hex_too_short(self):
        """Test is_hex rejects short strings."""
        assert is_hex("ab") is False


# ---------------------------------------------------------------------------
# TestGetStringStatistics
# ---------------------------------------------------------------------------


class TestGetStringStatistics:
    """Tests for get_string_statistics method."""

    def test_get_string_statistics_empty(self, tmp_path):
        """Test statistics with empty string list."""
        analyzer = _make_analyzer(tmp_path, cmdj_map={"izj": [], "izuj": []})
        result = analyzer.get_string_statistics()
        assert result["total_strings"] == 0
        assert result["avg_length"] == 0

    def test_get_string_statistics_single_string(self, tmp_path):
        """Test statistics with single string."""
        entries = [{"string": "test", "vaddr": 0x1000, "size": 4}]
        analyzer = _make_analyzer(
            tmp_path,
            cmdj_map={"izj": entries, "izuj": []},
        )
        result = analyzer.get_string_statistics()
        assert result["total_strings"] == 1
        assert result["avg_length"] == 4
        assert result["min_length"] == 4
        assert result["max_length"] == 4

    def test_get_string_statistics_multiple_strings(self, tmp_path):
        """Test statistics with multiple strings."""
        entries = [
            {"string": "test", "vaddr": 0x1000, "size": 4},
            {"string": "testing", "vaddr": 0x2000, "size": 7},
            {"string": "a_longer_string", "vaddr": 0x3000, "size": 15},
        ]
        analyzer = _make_analyzer(
            tmp_path,
            cmdj_map={"izj": entries, "izuj": []},
            strings={"min_length": 1},
        )
        result = analyzer.get_string_statistics()
        assert result["total_strings"] == 3
        assert "avg_length" in result
        assert result["min_length"] == 4
        assert result["max_length"] == 15

    def test_get_string_statistics_includes_charset_analysis(self, tmp_path):
        """Test that charset analysis is included."""
        entries = [{"string": "test", "vaddr": 0x1000, "size": 4}]
        analyzer = _make_analyzer(
            tmp_path,
            cmdj_map={"izj": entries, "izuj": []},
        )
        result = analyzer.get_string_statistics()
        assert "charset_analysis" in result
        assert isinstance(result["charset_analysis"], dict)


# ---------------------------------------------------------------------------
# TestAnalyzeCharset
# ---------------------------------------------------------------------------


class TestAnalyzeCharset:
    """Tests for _analyze_charset method."""

    def test_analyze_charset_empty(self, tmp_path):
        """Test charset analysis with empty list."""
        analyzer = _make_analyzer(tmp_path)
        result = analyzer._analyze_charset([])
        assert result["ascii"] == 0
        assert result["unicode"] == 0
        assert result["printable"] == 0
        assert result["alphanumeric"] == 0

    def test_analyze_charset_ascii_only(self, tmp_path):
        """Test charset analysis with ASCII strings."""
        analyzer = _make_analyzer(tmp_path)
        result = analyzer._analyze_charset(["test", "hello", "world"])
        assert result["ascii"] == 3

    def test_analyze_charset_printable(self, tmp_path):
        """Test charset analysis for printable strings."""
        analyzer = _make_analyzer(tmp_path)
        result = analyzer._analyze_charset(["test", "hello", "world"])
        assert result["printable"] == 3

    def test_analyze_charset_alphanumeric(self, tmp_path):
        """Test charset analysis for alphanumeric strings."""
        analyzer = _make_analyzer(tmp_path)
        result = analyzer._analyze_charset(["test123", "hello", "world"])
        assert result["alphanumeric"] >= 0

    def test_analyze_charset_mixed(self, tmp_path):
        """Test charset analysis with mixed content."""
        analyzer = _make_analyzer(tmp_path)
        result = analyzer._analyze_charset(["test", "hello123", "world!"])
        assert "ascii" in result
        assert "printable" in result
        assert "alphanumeric" in result


# ---------------------------------------------------------------------------
# TestAnalyzeMethod
# ---------------------------------------------------------------------------


class TestAnalyzeMethod:
    """Tests for analyze method."""

    def test_analyze_structure(self, tmp_path):
        """Test that analyze returns proper structure."""
        entries = [{"string": "test_string", "vaddr": 0x1000, "size": 11}]
        analyzer = _make_analyzer(
            tmp_path,
            cmdj_map={"izj": entries, "izuj": []},
        )
        result = analyzer.analyze()
        assert isinstance(result, dict)
        assert "strings" in result
        assert "total_strings" in result
        assert result["total_strings"] >= 0

    def test_analyze_empty_binary(self, tmp_path):
        """Test analyze on a binary with no strings."""
        analyzer = _make_analyzer(tmp_path, cmdj_map={"izj": [], "izuj": []})
        result = analyzer.analyze()
        assert isinstance(result, dict)
        assert result["total_strings"] == 0
        assert result["strings"] == []


# ---------------------------------------------------------------------------
# TestDomainHelpers – direct tests of string_domain functions
# ---------------------------------------------------------------------------


class TestDomainHelpers:
    """Direct tests of domain-layer string helpers."""

    def test_filter_strings_length_bounds(self):
        """Test filter_strings respects min/max length."""
        strings = ["ab", "abcd", "abcdefghij", "a" * 200]
        result = filter_strings(strings, min_length=4, max_length=100)
        assert "ab" not in result
        assert "abcd" in result
        assert "abcdefghij" in result
        assert ("a" * 200) not in result

    def test_filter_strings_strips_non_printable(self):
        """Test filter_strings cleans non-printable characters."""
        strings = ["hel\x00lo_world"]
        result = filter_strings(strings, min_length=4, max_length=100)
        assert len(result) == 1
        assert "\x00" not in result[0]

    def test_xor_string_roundtrip(self):
        """Test that XOR encoding is reversible."""
        original = "test"
        key = 42
        encoded = xor_string(original, key)
        decoded = xor_string(encoded, key)
        assert decoded == original

    def test_extract_strings_from_entries_basic(self):
        """Test extract_strings_from_entries with well-formed entries."""
        entries = [
            {"string": "hello", "vaddr": 0x1000},
            {"string": "hi", "vaddr": 0x2000},
            {"string": "world_test", "vaddr": 0x3000},
        ]
        result = extract_strings_from_entries(entries, min_length=4)
        assert "hello" in result
        assert "hi" not in result
        assert "world_test" in result

    def test_extract_strings_from_entries_none(self):
        """Test extract_strings_from_entries with None input."""
        result = extract_strings_from_entries(None, min_length=4)
        assert result == []
