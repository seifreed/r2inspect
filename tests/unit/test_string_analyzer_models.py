#!/usr/bin/env python3
"""Tests for string_analyzer module."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from r2inspect.modules.string_analyzer import StringAnalyzer


class TestStringAnalyzerInit:
    """Tests for StringAnalyzer initialization."""

    def test_string_analyzer_init_valid(self):
        """Test StringAnalyzer initialization with valid config."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        assert analyzer is not None
        assert analyzer.min_length == 4
        assert analyzer.max_length == 256
        assert analyzer.max_strings == 5000

    def test_string_analyzer_init_stores_config(self):
        """Test that init stores adapter and config."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        assert analyzer.adapter == adapter
        assert analyzer.config == config


class TestStringAnalyzerCategory:
    """Tests for get_category method."""

    def test_get_category(self):
        """Test that category is metadata."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        assert analyzer.get_category() == "metadata"


class TestStringAnalyzerDescription:
    """Tests for get_description method."""

    def test_get_description(self):
        """Test that description mentions string analysis."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        desc = analyzer.get_description()
        assert "string" in desc.lower()
        assert "extract" in desc.lower()


class TestExtractStrings:
    """Tests for extract_strings method."""

    def test_extract_strings_empty(self):
        """Test extracting strings when none are found."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = False
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch.object(analyzer, "_extract_ascii_strings", return_value=[]):
            result = analyzer.extract_strings()
            assert isinstance(result, list)

    def test_extract_strings_filters_duplicates(self):
        """Test that duplicates are removed."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch.object(analyzer, "_extract_ascii_strings", return_value=["test", "test", "other"]):
            with patch.object(analyzer, "_extract_unicode_strings", return_value=["test"]):
                result = analyzer.extract_strings()
                assert result.count("test") == 1

    def test_extract_strings_respects_max_strings(self):
        """Test that max_strings limit is respected."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 1
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = False
        config.typed_config.general.max_strings = 3

        analyzer = StringAnalyzer(adapter, config)
        strings = [f"string{i}" for i in range(10)]
        with patch.object(analyzer, "_extract_ascii_strings", return_value=strings):
            result = analyzer.extract_strings()
            assert len(result) <= 3

    def test_extract_strings_handles_exception(self):
        """Test exception handling in extract_strings."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch.object(analyzer, "_extract_ascii_strings", side_effect=Exception("Test error")):
            result = analyzer.extract_strings()
            assert isinstance(result, list)


class TestExtractAsciiStrings:
    """Tests for _extract_ascii_strings method."""

    def test_extract_ascii_strings_success(self):
        """Test successful ASCII string extraction."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = False
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch.object(analyzer, "_fetch_string_entries", return_value=[{"string": "test"}]):
            with patch("r2inspect.modules.string_analyzer.extract_strings_from_entries", return_value=["test"]):
                result = analyzer._extract_ascii_strings()
                assert isinstance(result, list)

    def test_extract_ascii_strings_exception(self):
        """Test exception handling in ASCII extraction."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = False
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch.object(analyzer, "_fetch_string_entries", side_effect=Exception("Test error")):
            result = analyzer._extract_ascii_strings()
            assert result == []


class TestExtractUnicodeStrings:
    """Tests for _extract_unicode_strings method."""

    def test_extract_unicode_strings_success(self):
        """Test successful Unicode string extraction."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = False
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch.object(analyzer, "_fetch_string_entries", return_value=[{"string": "test"}]):
            with patch("r2inspect.modules.string_analyzer.extract_strings_from_entries", return_value=["test"]):
                result = analyzer._extract_unicode_strings()
                assert isinstance(result, list)

    def test_extract_unicode_strings_exception(self):
        """Test exception handling in Unicode extraction."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = False
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch.object(analyzer, "_fetch_string_entries", side_effect=Exception("Test error")):
            result = analyzer._extract_unicode_strings()
            assert result == []


class TestSearchXor:
    """Tests for search_xor method."""

    def test_search_xor_success(self):
        """Test successful XOR search."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch("r2inspect.modules.string_analyzer.build_xor_matches", return_value=[{"xor_key": 42}]):
            result = analyzer.search_xor("test")
            assert isinstance(result, list)

    def test_search_xor_exception(self):
        """Test exception handling in XOR search."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch("r2inspect.modules.string_analyzer.build_xor_matches", side_effect=Exception("Test error")):
            result = analyzer.search_xor("test")
            assert result == []


class TestGetSuspiciousStrings:
    """Tests for get_suspicious_strings method."""

    def test_get_suspicious_strings_empty(self):
        """Test getting suspicious strings from empty list."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch.object(analyzer, "extract_strings", return_value=[]):
            result = analyzer.get_suspicious_strings()
            assert isinstance(result, list)

    def test_get_suspicious_strings_with_url(self):
        """Test detection of suspicious URLs."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch.object(analyzer, "extract_strings", return_value=["http://malware.com"]):
            result = analyzer.get_suspicious_strings()
            assert isinstance(result, list)


class TestDecodeStrings:
    """Tests for decode_strings method."""

    def test_decode_strings_empty(self):
        """Test decoding when no strings found."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch.object(analyzer, "extract_strings", return_value=[]):
            result = analyzer.decode_strings()
            assert result == []

    def test_decode_strings_with_base64(self):
        """Test decoding base64 strings."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch.object(analyzer, "extract_strings", return_value=["aGVsbG8="]):
            with patch("r2inspect.modules.string_analyzer.decode_base64", return_value={"decoded": "hello"}):
                result = analyzer.decode_strings()
                assert isinstance(result, list)

    def test_decode_strings_with_hex(self):
        """Test decoding hex strings."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch.object(analyzer, "extract_strings", return_value=["68656c6c6f"]):
            with patch("r2inspect.modules.string_analyzer.decode_hex", return_value={"decoded": "hello"}):
                result = analyzer.decode_strings()
                assert isinstance(result, list)


class TestDecodeBase64Method:
    """Tests for _decode_base64 method."""

    def test_decode_base64_method(self):
        """Test _decode_base64 wrapper method."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch("r2inspect.modules.string_analyzer.decode_base64", return_value={"decoded": "hello"}):
            result = analyzer._decode_base64("aGVsbG8=")
            assert result is not None


class TestDecodeHexMethod:
    """Tests for _decode_hex method."""

    def test_decode_hex_method(self):
        """Test _decode_hex wrapper method."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch("r2inspect.modules.string_analyzer.decode_hex", return_value={"decoded": "hello"}):
            result = analyzer._decode_hex("68656c6c6f")
            assert result is not None


class TestGetStringStatistics:
    """Tests for get_string_statistics method."""

    def test_get_string_statistics_empty(self):
        """Test statistics with empty string list."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch.object(analyzer, "extract_strings", return_value=[]):
            result = analyzer.get_string_statistics()
            assert result["total_strings"] == 0
            assert result["avg_length"] == 0

    def test_get_string_statistics_single_string(self):
        """Test statistics with single string."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch.object(analyzer, "extract_strings", return_value=["test"]):
            result = analyzer.get_string_statistics()
            assert result["total_strings"] == 1
            assert result["avg_length"] == 4
            assert result["min_length"] == 4
            assert result["max_length"] == 4

    def test_get_string_statistics_multiple_strings(self):
        """Test statistics with multiple strings."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch.object(analyzer, "extract_strings", return_value=["test", "testing", "t"]):
            result = analyzer.get_string_statistics()
            assert result["total_strings"] == 3
            assert "avg_length" in result
            assert result["min_length"] == 1
            assert result["max_length"] == 7

    def test_get_string_statistics_includes_charset_analysis(self):
        """Test that charset analysis is included."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch.object(analyzer, "extract_strings", return_value=["test"]):
            result = analyzer.get_string_statistics()
            assert "charset_analysis" in result
            assert isinstance(result["charset_analysis"], dict)


class TestAnalyzeCharset:
    """Tests for _analyze_charset method."""

    def test_analyze_charset_empty(self):
        """Test charset analysis with empty list."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        result = analyzer._analyze_charset([])
        assert result["ascii"] == 0
        assert result["unicode"] == 0
        assert result["printable"] == 0
        assert result["alphanumeric"] == 0

    def test_analyze_charset_ascii_only(self):
        """Test charset analysis with ASCII strings."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        result = analyzer._analyze_charset(["test", "hello", "world"])
        assert result["ascii"] == 3

    def test_analyze_charset_printable(self):
        """Test charset analysis for printable strings."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        result = analyzer._analyze_charset(["test", "hello", "world"])
        assert result["printable"] == 3

    def test_analyze_charset_alphanumeric(self):
        """Test charset analysis for alphanumeric strings."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        result = analyzer._analyze_charset(["test123", "hello", "world"])
        assert result["alphanumeric"] >= 0

    def test_analyze_charset_mixed(self):
        """Test charset analysis with mixed content."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 1
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        result = analyzer._analyze_charset(["test", "hello123", "world!"])
        assert "ascii" in result
        assert "printable" in result
        assert "alphanumeric" in result


class TestAnalyzeMethod:
    """Tests for analyze method."""

    def test_analyze_structure(self):
        """Test that analyze returns proper structure."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 256
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        config.typed_config.general.max_strings = 5000

        analyzer = StringAnalyzer(adapter, config)
        with patch.object(analyzer, "extract_strings", return_value=["test"]):
            with patch.object(analyzer, "_analysis_context"):
                # Mock the _analysis_context as a context manager
                analyzer._analysis_context = MagicMock()
                analyzer._analysis_context.__enter__ = MagicMock(return_value=None)
                analyzer._analysis_context.__exit__ = MagicMock(return_value=None)
                analyzer._log_info = Mock()
                result = analyzer.analyze()
                assert isinstance(result, dict)
