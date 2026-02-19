"""Comprehensive tests for string_analyzer.py extraction and encoding."""

from unittest.mock import Mock, patch

import pytest

from r2inspect.modules.string_analyzer import StringAnalyzer


class TestStringAnalyzerBasics:
    """Test basic StringAnalyzer functionality."""

    def test_init(self):
        """Test analyzer initialization."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        
        analyzer = StringAnalyzer(adapter, config)
        
        assert analyzer.adapter == adapter
        assert analyzer.min_length == 4
        assert analyzer.max_length == 1000
        assert analyzer.max_strings == 5000

    def test_get_category(self):
        """Test category retrieval."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        
        analyzer = StringAnalyzer(adapter, config)
        
        assert analyzer.get_category() == "metadata"

    def test_get_description(self):
        """Test description retrieval."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        
        analyzer = StringAnalyzer(adapter, config)
        
        description = analyzer.get_description()
        assert "string" in description.lower()

    def test_analyze_basic(self):
        """Test basic analyze method."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = False
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch.object(analyzer, "_analysis_context"):
            with patch.object(analyzer, "extract_strings") as mock_extract:
                mock_extract.return_value = ["test1", "test2", "test3"]
                
                result = analyzer.analyze()
        
        assert "strings" in result
        assert "total_strings" in result


class TestStringExtraction:
    """Test string extraction methods."""

    def test_extract_strings_ascii_only(self):
        """Test extracting ASCII strings only."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = False
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch.object(analyzer, "_extract_ascii_strings") as mock_ascii:
            mock_ascii.return_value = ["string1", "string2"]
            
            result = analyzer.extract_strings()
        
        assert len(result) == 2
        assert "string1" in result

    def test_extract_strings_unicode_only(self):
        """Test extracting Unicode strings only."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        config.typed_config.strings.extract_ascii = False
        config.typed_config.strings.extract_unicode = True
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch.object(analyzer, "_extract_unicode_strings") as mock_unicode:
            mock_unicode.return_value = ["unicode1", "unicode2"]
            
            result = analyzer.extract_strings()
        
        assert len(result) == 2
        assert "unicode1" in result

    def test_extract_strings_both_types(self):
        """Test extracting both ASCII and Unicode."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch.object(analyzer, "_extract_ascii_strings") as mock_ascii:
            with patch.object(analyzer, "_extract_unicode_strings") as mock_unicode:
                mock_ascii.return_value = ["ascii1", "ascii2"]
                mock_unicode.return_value = ["unicode1", "unicode2"]
                
                result = analyzer.extract_strings()
        
        assert len(result) == 4

    def test_extract_strings_removes_duplicates(self):
        """Test that duplicate strings are removed."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch.object(analyzer, "_extract_ascii_strings") as mock_ascii:
            with patch.object(analyzer, "_extract_unicode_strings") as mock_unicode:
                mock_ascii.return_value = ["duplicate", "unique1"]
                mock_unicode.return_value = ["duplicate", "unique2"]
                
                result = analyzer.extract_strings()
        
        # Should have 3 unique strings
        assert len(result) == 3
        assert "duplicate" in result
        assert result.count("duplicate") == 1

    def test_extract_strings_limited_by_max(self):
        """Test that string count is limited by max_strings."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = False
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch.object(analyzer, "_extract_ascii_strings") as mock_ascii:
            # Return 10 strings
            mock_ascii.return_value = [f"string{i}" for i in range(10)]
            
            result = analyzer.extract_strings()
        
        # Should be limited to 5
        assert len(result) == 5

    def test_extract_strings_exception_handling(self):
        """Test exception handling in string extraction."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = False
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch.object(analyzer, "_extract_ascii_strings") as mock_ascii:
            mock_ascii.side_effect = Exception("Extraction error")
            
            result = analyzer.extract_strings()
        
        # Should return empty list on error
        assert result == []


class TestASCIIStringExtraction:
    """Test ASCII string extraction."""

    def test_extract_ascii_strings_success(self):
        """Test successful ASCII string extraction."""
        adapter = Mock()
        r2 = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        
        analyzer = StringAnalyzer(adapter, config)
        analyzer.r2 = r2
        
        with patch("r2inspect.modules.string_analyzer.cmdj_helper") as mock_cmdj:
            mock_cmdj.return_value = [
                {"string": "test_string_1", "length": 13},
                {"string": "test_string_2", "length": 13}
            ]
            
            with patch("r2inspect.modules.string_analyzer.extract_strings_from_entries") as mock_extract:
                mock_extract.return_value = ["test_string_1", "test_string_2"]
                
                result = analyzer._extract_ascii_strings()
        
        assert len(result) == 2
        assert "test_string_1" in result

    def test_extract_ascii_strings_exception(self):
        """Test ASCII extraction with exception."""
        adapter = Mock()
        r2 = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        
        analyzer = StringAnalyzer(adapter, config)
        analyzer.r2 = r2
        
        with patch("r2inspect.modules.string_analyzer.cmdj_helper") as mock_cmdj:
            mock_cmdj.side_effect = Exception("Command error")
            
            result = analyzer._extract_ascii_strings()
        
        assert result == []


class TestUnicodeStringExtraction:
    """Test Unicode string extraction."""

    def test_extract_unicode_strings_success(self):
        """Test successful Unicode string extraction."""
        adapter = Mock()
        r2 = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        
        analyzer = StringAnalyzer(adapter, config)
        analyzer.r2 = r2
        
        with patch("r2inspect.modules.string_analyzer.cmdj_helper") as mock_cmdj:
            mock_cmdj.return_value = [
                {"string": "unicode_test", "length": 12}
            ]
            
            with patch("r2inspect.modules.string_analyzer.extract_strings_from_entries") as mock_extract:
                mock_extract.return_value = ["unicode_test"]
                
                result = analyzer._extract_unicode_strings()
        
        assert len(result) == 1
        assert "unicode_test" in result

    def test_extract_unicode_strings_exception(self):
        """Test Unicode extraction with exception."""
        adapter = Mock()
        r2 = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        
        analyzer = StringAnalyzer(adapter, config)
        analyzer.r2 = r2
        
        with patch("r2inspect.modules.string_analyzer.cmdj_helper") as mock_cmdj:
            mock_cmdj.side_effect = Exception("Unicode error")
            
            result = analyzer._extract_unicode_strings()
        
        assert result == []


class TestFetchStringEntries:
    """Test fetching string entries from r2."""

    def test_fetch_string_entries_list_result(self):
        """Test fetching entries with list result."""
        adapter = Mock()
        r2 = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        
        analyzer = StringAnalyzer(adapter, config)
        analyzer.r2 = r2
        
        with patch("r2inspect.modules.string_analyzer.cmdj_helper") as mock_cmdj:
            mock_cmdj.return_value = [{"string": "test"}]
            
            result = analyzer._fetch_string_entries("izj")
        
        assert isinstance(result, list)
        assert len(result) == 1

    def test_fetch_string_entries_non_list_result(self):
        """Test fetching entries with non-list result."""
        adapter = Mock()
        r2 = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        
        analyzer = StringAnalyzer(adapter, config)
        analyzer.r2 = r2
        
        with patch("r2inspect.modules.string_analyzer.cmdj_helper") as mock_cmdj:
            mock_cmdj.return_value = {"not": "a list"}
            
            result = analyzer._fetch_string_entries("izj")
        
        assert result == []


class TestXORSearch:
    """Test XOR string search."""

    def test_search_xor_success(self):
        """Test successful XOR search."""
        adapter = Mock()
        r2 = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        
        analyzer = StringAnalyzer(adapter, config)
        analyzer.r2 = r2
        
        with patch("r2inspect.modules.string_analyzer.build_xor_matches") as mock_xor:
            mock_xor.return_value = [
                {"key": 0x42, "decoded": "hidden_string", "offset": 0x1000}
            ]
            
            result = analyzer.search_xor("test")
        
        assert len(result) == 1
        assert result[0]["key"] == 0x42

    def test_search_xor_exception(self):
        """Test XOR search with exception."""
        adapter = Mock()
        r2 = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        
        analyzer = StringAnalyzer(adapter, config)
        analyzer.r2 = r2
        
        with patch("r2inspect.modules.string_analyzer.build_xor_matches") as mock_xor:
            mock_xor.side_effect = Exception("XOR error")
            
            result = analyzer.search_xor("test")
        
        assert result == []


class TestSuspiciousStrings:
    """Test suspicious string detection."""

    def test_get_suspicious_strings(self):
        """Test finding suspicious strings."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = False
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch.object(analyzer, "extract_strings") as mock_extract:
            mock_extract.return_value = ["CreateProcess", "ShellExecute", "benign"]
            
            with patch("r2inspect.modules.string_analyzer.find_suspicious") as mock_find:
                mock_find.return_value = [
                    {"string": "CreateProcess", "category": "process_creation"},
                    {"string": "ShellExecute", "category": "process_creation"}
                ]
                
                result = analyzer.get_suspicious_strings()
        
        assert len(result) == 2


class TestStringDecoding:
    """Test string decoding methods."""

    def test_decode_strings_base64(self):
        """Test decoding base64 strings."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = False
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch.object(analyzer, "extract_strings") as mock_extract:
            mock_extract.return_value = ["SGVsbG8gV29ybGQ="]  # "Hello World" in base64
            
            with patch("r2inspect.modules.string_analyzer.decode_base64") as mock_decode:
                mock_decode.return_value = {
                    "encoded": "SGVsbG8gV29ybGQ=",
                    "decoded": "Hello World",
                    "encoding": "base64"
                }
                
                result = analyzer.decode_strings()
        
        assert len(result) == 1
        assert result[0]["encoding"] == "base64"

    def test_decode_strings_hex(self):
        """Test decoding hex strings."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = False
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch.object(analyzer, "extract_strings") as mock_extract:
            mock_extract.return_value = ["48656c6c6f"]  # "Hello" in hex
            
            with patch("r2inspect.modules.string_analyzer.decode_hex") as mock_decode:
                mock_decode.return_value = {
                    "encoded": "48656c6c6f",
                    "decoded": "Hello",
                    "encoding": "hex"
                }
                
                result = analyzer.decode_strings()
        
        assert len(result) >= 1

    def test_decode_strings_multiple_types(self):
        """Test decoding multiple encoding types."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = False
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch.object(analyzer, "extract_strings") as mock_extract:
            mock_extract.return_value = ["SGVsbG8=", "48656c6c6f"]
            
            with patch("r2inspect.modules.string_analyzer.decode_base64") as mock_b64:
                with patch("r2inspect.modules.string_analyzer.decode_hex") as mock_hex:
                    mock_b64.side_effect = [{"encoding": "base64"}, None]
                    mock_hex.side_effect = [None, {"encoding": "hex"}]
                    
                    result = analyzer.decode_strings()
        
        # Should have at least the successful decodings
        assert len(result) >= 1

    def test_decode_base64_method(self):
        """Test _decode_base64 method."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch("r2inspect.modules.string_analyzer.decode_base64") as mock_decode:
            mock_decode.return_value = {"decoded": "test"}
            
            result = analyzer._decode_base64("dGVzdA==")
        
        assert result is not None
        assert result["decoded"] == "test"

    def test_decode_hex_method(self):
        """Test _decode_hex method."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch("r2inspect.modules.string_analyzer.decode_hex") as mock_decode:
            mock_decode.return_value = {"decoded": "test"}
            
            result = analyzer._decode_hex("74657374")
        
        assert result is not None
        assert result["decoded"] == "test"


class TestStringStatistics:
    """Test string statistics calculation."""

    def test_get_string_statistics_basic(self):
        """Test basic statistics calculation."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = False
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch.object(analyzer, "extract_strings") as mock_extract:
            mock_extract.return_value = ["test", "hello", "world"]
            
            result = analyzer.get_string_statistics()
        
        assert result["total_strings"] == 3
        assert result["avg_length"] > 0
        assert result["min_length"] >= 4
        assert result["max_length"] >= 4

    def test_get_string_statistics_empty(self):
        """Test statistics with no strings."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = False
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch.object(analyzer, "extract_strings") as mock_extract:
            mock_extract.return_value = []
            
            result = analyzer.get_string_statistics()
        
        assert result["total_strings"] == 0
        assert result["avg_length"] == 0
        assert result["min_length"] == 0
        assert result["max_length"] == 0

    def test_get_string_statistics_with_charset(self):
        """Test statistics with charset analysis."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = False
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch.object(analyzer, "extract_strings") as mock_extract:
            mock_extract.return_value = ["test", "hello", "world"]
            
            result = analyzer.get_string_statistics()
        
        assert "charset_analysis" in result
        assert "ascii" in result["charset_analysis"]


class TestCharsetAnalysis:
    """Test character set analysis."""

    def test_analyze_charset_ascii_only(self):
        """Test charset analysis with ASCII only."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        
        analyzer = StringAnalyzer(adapter, config)
        
        strings = ["test", "hello", "world"]
        result = analyzer._analyze_charset(strings)
        
        assert result["ascii"] == 3
        assert result["unicode"] == 0

    def test_analyze_charset_unicode(self):
        """Test charset analysis with Unicode."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        
        analyzer = StringAnalyzer(adapter, config)
        
        strings = ["test", "hello", "世界"]  # ASCII + Unicode
        result = analyzer._analyze_charset(strings)
        
        assert result["ascii"] == 2
        assert result["unicode"] == 1

    def test_analyze_charset_printable(self):
        """Test charset analysis for printable strings."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        
        analyzer = StringAnalyzer(adapter, config)
        
        strings = ["test", "hello world"]
        result = analyzer._analyze_charset(strings)
        
        assert result["printable"] == 2

    def test_analyze_charset_alphanumeric(self):
        """Test charset analysis for alphanumeric strings."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        
        analyzer = StringAnalyzer(adapter, config)
        
        strings = ["test123", "hello", "world!"]
        result = analyzer._analyze_charset(strings)
        
        # Only "test123" and "hello" are fully alphanumeric
        assert result["alphanumeric"] >= 1


class TestImportErrorScenarios:
    """Test behavior when optional dependencies are missing."""

    def test_extract_strings_cmdj_import_error(self):
        """Test extraction when cmdj_helper has import issues."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = False
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch("r2inspect.modules.string_analyzer.cmdj_helper") as mock_cmdj:
            mock_cmdj.side_effect = ImportError("Module not found")
            
            result = analyzer.extract_strings()
        
        # Should handle gracefully
        assert isinstance(result, list)

    def test_decode_strings_import_error(self):
        """Test decoding when import fails."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = False
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch.object(analyzer, "extract_strings") as mock_extract:
            mock_extract.return_value = ["test"]
            
            with patch("r2inspect.modules.string_analyzer.decode_base64") as mock_decode:
                # Return None instead of raising exception
                mock_decode.return_value = None
                
                result = analyzer.decode_strings()
        
        # Should handle gracefully and continue
        assert isinstance(result, list)


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_extract_strings_very_long_strings(self):
        """Test handling of very long strings."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 100
        config.typed_config.general.max_strings = 5000
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = False
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch.object(analyzer, "_extract_ascii_strings") as mock_ascii:
            # String longer than max_length
            mock_ascii.return_value = ["x" * 200]
            
            with patch("r2inspect.modules.string_analyzer.filter_strings") as mock_filter:
                mock_filter.return_value = []  # Filtered out
                
                result = analyzer.extract_strings()
        
        assert len(result) == 0

    def test_extract_strings_very_short_strings(self):
        """Test handling of very short strings."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 10
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = False
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch.object(analyzer, "_extract_ascii_strings") as mock_ascii:
            # Strings shorter than min_length
            mock_ascii.return_value = ["ab", "cd"]
            
            with patch("r2inspect.modules.string_analyzer.filter_strings") as mock_filter:
                mock_filter.return_value = []  # Filtered out
                
                result = analyzer.extract_strings()
        
        assert len(result) == 0

    def test_extract_strings_empty_result(self):
        """Test extraction with empty result."""
        adapter = Mock()
        config = Mock()
        config.typed_config.strings.min_length = 4
        config.typed_config.strings.max_length = 1000
        config.typed_config.general.max_strings = 5000
        config.typed_config.strings.extract_ascii = True
        config.typed_config.strings.extract_unicode = True
        
        analyzer = StringAnalyzer(adapter, config)
        
        with patch.object(analyzer, "_extract_ascii_strings") as mock_ascii:
            with patch.object(analyzer, "_extract_unicode_strings") as mock_unicode:
                mock_ascii.return_value = []
                mock_unicode.return_value = []
                
                result = analyzer.extract_strings()
        
        assert result == []
