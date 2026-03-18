"""Comprehensive tests for string_analyzer.py extraction and encoding."""

from dataclasses import replace

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.config_schemas.schemas import GeneralConfig, StringsConfig
from r2inspect.modules.string_analyzer import StringAnalyzer


class FakeR2:
    """Lightweight fake r2pipe instance for testing."""

    def __init__(self, cmdj_map=None, cmd_map=None):
        self.cmdj_map = cmdj_map or {}
        self.cmd_map = cmd_map or {}

    def cmdj(self, command):
        return self.cmdj_map.get(command, {})

    def cmd(self, command):
        return self.cmd_map.get(command, "")


def _make_adapter(cmdj_map=None, cmd_map=None):
    """Create a real R2PipeAdapter backed by a FakeR2."""
    fake = FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map)
    return R2PipeAdapter(fake)


def _make_config(tmp_path):
    """Create a real Config instance using a temp directory."""
    config_file = tmp_path / "config.json"
    return Config(str(config_file))


class TestStringAnalyzerBasics:
    """Test basic StringAnalyzer functionality."""

    def test_init(self, tmp_path):
        """Test analyzer initialization."""
        adapter = _make_adapter()
        config = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, config)

        assert analyzer.adapter is adapter
        assert analyzer.min_length == config.typed_config.strings.min_length
        assert analyzer.max_length == config.typed_config.strings.max_length
        assert analyzer.max_strings == config.typed_config.general.max_strings

    def test_get_category(self, tmp_path):
        """Test category retrieval."""
        adapter = _make_adapter()
        config = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, config)

        assert analyzer.get_category() == "metadata"

    def test_get_description(self, tmp_path):
        """Test description retrieval."""
        adapter = _make_adapter()
        config = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, config)

        description = analyzer.get_description()
        assert "string" in description.lower()

    def test_analyze_basic(self, tmp_path):
        """Test basic analyze method returns correct structure."""
        # Provide some string entries that the izj command will return
        string_entries = [
            {
                "string": "test_one_string",
                "length": 15,
                "vaddr": 0x1000,
                "paddr": 0x400,
                "section": ".data",
                "type": "ascii",
                "size": 15,
            },
            {
                "string": "test_two_string",
                "length": 15,
                "vaddr": 0x2000,
                "paddr": 0x500,
                "section": ".data",
                "type": "ascii",
                "size": 15,
            },
        ]
        adapter = _make_adapter(cmdj_map={"izj": string_entries})
        config = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.analyze()

        assert "strings" in result
        assert "total_strings" in result


class TestStringExtraction:
    """Test string extraction methods."""

    def test_extract_strings_ascii_only(self, tmp_path):
        """Test extracting ASCII strings only."""
        string_entries = [
            {
                "string": "string_one_test",
                "length": 15,
                "vaddr": 0x1000,
                "paddr": 0x400,
                "section": ".data",
                "type": "ascii",
                "size": 15,
            },
            {
                "string": "string_two_test",
                "length": 15,
                "vaddr": 0x2000,
                "paddr": 0x500,
                "section": ".data",
                "type": "ascii",
                "size": 15,
            },
        ]
        adapter = _make_adapter(cmdj_map={"izj": string_entries})
        config = _make_config(tmp_path)
        # Ensure only ASCII extraction is enabled
        config._typed_config = replace(
            config._typed_config,
            strings=StringsConfig(extract_ascii=True, extract_unicode=False),
        )
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.extract_strings()

        assert len(result) == 2
        assert "string_one_test" in result

    def test_extract_strings_unicode_only(self, tmp_path):
        """Test extracting Unicode strings only."""
        unicode_entries = [
            {
                "string": "unicode_one_test",
                "length": 16,
                "vaddr": 0x1000,
                "paddr": 0x400,
                "section": ".data",
                "type": "wide",
                "size": 32,
            },
            {
                "string": "unicode_two_test",
                "length": 16,
                "vaddr": 0x2000,
                "paddr": 0x500,
                "section": ".data",
                "type": "wide",
                "size": 32,
            },
        ]
        adapter = _make_adapter(cmdj_map={"izuj": unicode_entries})
        config = _make_config(tmp_path)
        config._typed_config = replace(
            config._typed_config,
            strings=StringsConfig(extract_ascii=False, extract_unicode=True),
        )
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.extract_strings()

        assert len(result) == 2
        assert "unicode_one_test" in result

    def test_extract_strings_both_types(self, tmp_path):
        """Test extracting both ASCII and Unicode."""
        ascii_entries = [
            {
                "string": "ascii_one_test",
                "length": 14,
                "vaddr": 0x1000,
                "paddr": 0x400,
                "section": ".data",
                "type": "ascii",
                "size": 14,
            },
            {
                "string": "ascii_two_test",
                "length": 14,
                "vaddr": 0x2000,
                "paddr": 0x500,
                "section": ".data",
                "type": "ascii",
                "size": 14,
            },
        ]
        unicode_entries = [
            {
                "string": "unicode_one_test",
                "length": 16,
                "vaddr": 0x3000,
                "paddr": 0x600,
                "section": ".data",
                "type": "wide",
                "size": 32,
            },
            {
                "string": "unicode_two_test",
                "length": 16,
                "vaddr": 0x4000,
                "paddr": 0x700,
                "section": ".data",
                "type": "wide",
                "size": 32,
            },
        ]
        adapter = _make_adapter(cmdj_map={"izj": ascii_entries, "izuj": unicode_entries})
        config = _make_config(tmp_path)
        config._typed_config = replace(
            config._typed_config,
            strings=StringsConfig(extract_ascii=True, extract_unicode=True),
        )
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.extract_strings()

        assert len(result) == 4

    def test_extract_strings_removes_duplicates(self, tmp_path):
        """Test that duplicate strings are removed."""
        ascii_entries = [
            {
                "string": "duplicate_string",
                "length": 16,
                "vaddr": 0x1000,
                "paddr": 0x400,
                "section": ".data",
                "type": "ascii",
                "size": 16,
            },
            {
                "string": "unique_one_str",
                "length": 14,
                "vaddr": 0x2000,
                "paddr": 0x500,
                "section": ".data",
                "type": "ascii",
                "size": 14,
            },
        ]
        unicode_entries = [
            {
                "string": "duplicate_string",
                "length": 16,
                "vaddr": 0x3000,
                "paddr": 0x600,
                "section": ".data",
                "type": "wide",
                "size": 32,
            },
            {
                "string": "unique_two_str",
                "length": 14,
                "vaddr": 0x4000,
                "paddr": 0x700,
                "section": ".data",
                "type": "wide",
                "size": 32,
            },
        ]
        adapter = _make_adapter(cmdj_map={"izj": ascii_entries, "izuj": unicode_entries})
        config = _make_config(tmp_path)
        config._typed_config = replace(
            config._typed_config,
            strings=StringsConfig(extract_ascii=True, extract_unicode=True),
        )
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.extract_strings()

        # Should have 3 unique strings (duplicate removed)
        assert len(result) == 3
        assert "duplicate_string" in result
        assert result.count("duplicate_string") == 1

    def test_extract_strings_limited_by_max(self, tmp_path):
        """Test that string count is limited by max_strings."""
        # Create 10 strings, each long enough to pass min_length filter
        entries = [
            {
                "string": f"string_number_{i:04d}",
                "length": 18,
                "vaddr": 0x1000 + i * 0x100,
                "paddr": 0x400 + i * 0x100,
                "section": ".data",
                "type": "ascii",
                "size": 18,
            }
            for i in range(10)
        ]
        adapter = _make_adapter(cmdj_map={"izj": entries})
        config = _make_config(tmp_path)
        config._typed_config = replace(
            config._typed_config,
            strings=StringsConfig(extract_ascii=True, extract_unicode=False),
            general=GeneralConfig(max_strings=5),
        )
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.extract_strings()

        # Should be limited to 5
        assert len(result) == 5

    def test_extract_strings_exception_handling(self, tmp_path):
        """Test exception handling in string extraction via adapter that raises."""

        class BrokenR2:
            """R2 instance that raises on cmdj."""

            def cmdj(self, command):
                raise RuntimeError("Extraction error")

            def cmd(self, command):
                raise RuntimeError("Extraction error")

        adapter = R2PipeAdapter(BrokenR2())
        config = _make_config(tmp_path)
        config._typed_config = replace(
            config._typed_config,
            strings=StringsConfig(extract_ascii=True, extract_unicode=False),
        )
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.extract_strings()

        # Should return empty list on error (or gracefully handle it)
        assert isinstance(result, list)


class TestASCIIStringExtraction:
    """Test ASCII string extraction."""

    def test_extract_ascii_strings_success(self, tmp_path):
        """Test successful ASCII string extraction."""
        string_entries = [
            {
                "string": "test_string_1xx",
                "length": 15,
                "vaddr": 0x1000,
                "paddr": 0x400,
                "section": ".data",
                "type": "ascii",
                "size": 15,
            },
            {
                "string": "test_string_2xx",
                "length": 15,
                "vaddr": 0x2000,
                "paddr": 0x500,
                "section": ".data",
                "type": "ascii",
                "size": 15,
            },
        ]
        adapter = _make_adapter(cmdj_map={"izj": string_entries})
        config = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer._extract_ascii_strings()

        assert len(result) == 2
        assert "test_string_1xx" in result

    def test_extract_ascii_strings_exception(self, tmp_path):
        """Test ASCII extraction with exception."""

        class BrokenR2:
            def cmdj(self, command):
                raise RuntimeError("Command error")

            def cmd(self, command):
                raise RuntimeError("Command error")

        adapter = R2PipeAdapter(BrokenR2())
        config = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer._extract_ascii_strings()

        assert result == []


class TestUnicodeStringExtraction:
    """Test Unicode string extraction."""

    def test_extract_unicode_strings_success(self, tmp_path):
        """Test successful Unicode string extraction."""
        unicode_entries = [
            {
                "string": "unicode_test_xx",
                "length": 15,
                "vaddr": 0x1000,
                "paddr": 0x400,
                "section": ".data",
                "type": "wide",
                "size": 30,
            },
        ]
        adapter = _make_adapter(cmdj_map={"izuj": unicode_entries})
        config = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer._extract_unicode_strings()

        assert len(result) == 1
        assert "unicode_test_xx" in result

    def test_extract_unicode_strings_exception(self, tmp_path):
        """Test Unicode extraction with exception."""

        class BrokenR2:
            def cmdj(self, command):
                raise RuntimeError("Unicode error")

            def cmd(self, command):
                raise RuntimeError("Unicode error")

        adapter = R2PipeAdapter(BrokenR2())
        config = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer._extract_unicode_strings()

        assert result == []


class TestFetchStringEntries:
    """Test fetching string entries from r2."""

    def test_fetch_string_entries_list_result(self, tmp_path):
        """Test fetching entries with list result."""
        entries = [
            {
                "string": "test_entry_str",
                "length": 14,
                "vaddr": 0x1000,
                "paddr": 0x400,
                "section": ".data",
                "type": "ascii",
                "size": 14,
            }
        ]
        adapter = _make_adapter(cmdj_map={"izj": entries})
        config = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer._fetch_string_entries("izj")

        assert isinstance(result, list)
        assert len(result) == 1

    def test_fetch_string_entries_non_list_result(self, tmp_path):
        """Test fetching entries with non-list result returns empty list."""
        # Return a dict instead of a list for the izj command
        adapter = _make_adapter(cmdj_map={"izj": {"not": "a list"}})
        config = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer._fetch_string_entries("izj")

        assert result == []


class TestXORSearch:
    """Test XOR string search."""

    def test_search_xor_success(self, tmp_path):
        """Test successful XOR search that finds matches."""

        class FakeR2WithSearch:
            """R2 that returns search results for hex patterns."""

            def cmdj(self, command):
                return {}

            def cmd(self, command):
                # Return a search hit for any /x command
                if command.startswith("/x "):
                    return "0x1000 0 1\n"
                return ""

        class FakeAdapterWithSearch:
            """Adapter with search_hex support."""

            def __init__(self, r2):
                self._r2 = r2
                self._cache = {}
                self.r2 = r2

            def search_hex(self, pattern):
                return self._r2.cmd(f"/x {pattern}")

            def cmdj(self, command):
                return self._r2.cmdj(command)

            def cmd(self, command):
                return self._r2.cmd(command)

        fake_r2 = FakeR2WithSearch()
        adapter = FakeAdapterWithSearch(fake_r2)
        config = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, config)
        analyzer.r2 = adapter

        result = analyzer.search_xor("test")

        assert isinstance(result, list)
        # XOR search iterates keys 1-255, any match with the pattern will yield results
        assert len(result) > 0
        # Each entry has the expected structure
        assert "xor_key" in result[0]
        assert "addresses" in result[0]

    def test_search_xor_no_matches(self, tmp_path):
        """Test XOR search with no matches."""
        # Default FakeR2 returns "" for cmd and {} for cmdj, which yields no search results
        adapter = _make_adapter()
        config = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.search_xor("test")

        assert isinstance(result, list)
        # search_hex via search_helpers checks for adapter.search_hex -- FakeR2-based adapter
        # doesn't have it, so it returns "" for each key, meaning no matches
        assert result == []

    def test_search_xor_exception(self, tmp_path):
        """Test XOR search with exception returns empty list."""

        class ExplodingAdapter:
            """Adapter whose search_hex raises."""

            def search_hex(self, pattern):
                raise RuntimeError("XOR error")

            def cmdj(self, command):
                return {}

            def cmd(self, command):
                return ""

        adapter = ExplodingAdapter()
        config = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, config)
        analyzer.r2 = adapter

        result = analyzer.search_xor("test")

        assert result == []


class TestSuspiciousStrings:
    """Test suspicious string detection."""

    def test_get_suspicious_strings(self, tmp_path):
        """Test finding suspicious strings in extracted data."""
        # Use strings that match the SUSPICIOUS_PATTERNS in string_domain.py:
        # "api_calls" pattern matches VirtualAlloc, WriteProcessMemory, CreateRemoteThread, LoadLibrary
        # "urls" pattern matches http(s)://...
        string_entries = [
            {
                "string": "call VirtualAlloc here",
                "length": 21,
                "vaddr": 0x1000,
                "paddr": 0x400,
                "section": ".data",
                "type": "ascii",
                "size": 21,
            },
            {
                "string": "https://malware.example.com/payload",
                "length": 35,
                "vaddr": 0x2000,
                "paddr": 0x500,
                "section": ".data",
                "type": "ascii",
                "size": 35,
            },
            {
                "string": "benign_string_val",
                "length": 17,
                "vaddr": 0x3000,
                "paddr": 0x600,
                "section": ".data",
                "type": "ascii",
                "size": 17,
            },
        ]
        adapter = _make_adapter(cmdj_map={"izj": string_entries})
        config = _make_config(tmp_path)
        config._typed_config = replace(
            config._typed_config,
            strings=StringsConfig(extract_ascii=True, extract_unicode=False),
        )
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.get_suspicious_strings()

        # find_suspicious uses regex patterns from SUSPICIOUS_PATTERNS
        assert isinstance(result, list)
        assert len(result) >= 2
        suspicious_strings = [entry["string"] for entry in result]
        assert any("VirtualAlloc" in s for s in suspicious_strings)
        assert any("https://" in s for s in suspicious_strings)


class TestStringDecoding:
    """Test string decoding methods."""

    def test_decode_strings_base64(self, tmp_path):
        """Test decoding base64 strings found in the binary."""
        # SGVsbG8gV29ybGQh -> "Hello World!" (valid base64, printable result)
        string_entries = [
            {
                "string": "SGVsbG8gV29ybGQh",
                "length": 16,
                "vaddr": 0x1000,
                "paddr": 0x400,
                "section": ".data",
                "type": "ascii",
                "size": 16,
            },
        ]
        adapter = _make_adapter(cmdj_map={"izj": string_entries})
        config = _make_config(tmp_path)
        config._typed_config = replace(
            config._typed_config,
            strings=StringsConfig(extract_ascii=True, extract_unicode=False),
        )
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.decode_strings()

        # The base64 string should be decoded
        base64_results = [r for r in result if r.get("encoding") == "base64"]
        assert len(base64_results) >= 1
        assert base64_results[0]["decoded"] == "Hello World!"

    def test_decode_strings_hex(self, tmp_path):
        """Test decoding hex strings found in the binary."""
        # 48656c6c6f -> "Hello" (valid hex, printable result)
        string_entries = [
            {
                "string": "48656c6c6f",
                "length": 10,
                "vaddr": 0x1000,
                "paddr": 0x400,
                "section": ".data",
                "type": "ascii",
                "size": 10,
            },
        ]
        adapter = _make_adapter(cmdj_map={"izj": string_entries})
        config = _make_config(tmp_path)
        config._typed_config = replace(
            config._typed_config,
            strings=StringsConfig(extract_ascii=True, extract_unicode=False),
        )
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.decode_strings()

        hex_results = [r for r in result if r.get("encoding") == "hex"]
        assert len(hex_results) >= 1
        assert hex_results[0]["decoded"] == "Hello"

    def test_decode_strings_multiple_types(self, tmp_path):
        """Test decoding multiple encoding types."""
        string_entries = [
            {
                "string": "SGVsbG8gV29ybGQh",
                "length": 16,
                "vaddr": 0x1000,
                "paddr": 0x400,
                "section": ".data",
                "type": "ascii",
                "size": 16,
            },
            {
                "string": "48656c6c6f",
                "length": 10,
                "vaddr": 0x2000,
                "paddr": 0x500,
                "section": ".data",
                "type": "ascii",
                "size": 10,
            },
        ]
        adapter = _make_adapter(cmdj_map={"izj": string_entries})
        config = _make_config(tmp_path)
        config._typed_config = replace(
            config._typed_config,
            strings=StringsConfig(extract_ascii=True, extract_unicode=False),
        )
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.decode_strings()

        # Should have at least one base64 and one hex decoded entry
        assert len(result) >= 2

    def test_decode_base64_method(self, tmp_path):
        """Test _decode_base64 method with a real base64 string."""
        adapter = _make_adapter()
        config = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, config)

        # "dGVzdA==" is base64 for "test" -- but it's only 8 chars, passes is_base64
        result = analyzer._decode_base64("dGVzdA==")

        assert result is not None
        assert result["decoded"] == "test"

    def test_decode_hex_method(self, tmp_path):
        """Test _decode_hex method with a real hex string."""
        adapter = _make_adapter()
        config = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, config)

        # "74657374" is hex for "test"
        result = analyzer._decode_hex("74657374")

        assert result is not None
        assert result["decoded"] == "test"


class TestStringStatistics:
    """Test string statistics calculation."""

    def test_get_string_statistics_basic(self, tmp_path):
        """Test basic statistics calculation."""
        string_entries = [
            {
                "string": "test_str",
                "length": 8,
                "vaddr": 0x1000,
                "paddr": 0x400,
                "section": ".data",
                "type": "ascii",
                "size": 8,
            },
            {
                "string": "hello_world",
                "length": 11,
                "vaddr": 0x2000,
                "paddr": 0x500,
                "section": ".data",
                "type": "ascii",
                "size": 11,
            },
            {
                "string": "world_str",
                "length": 9,
                "vaddr": 0x3000,
                "paddr": 0x600,
                "section": ".data",
                "type": "ascii",
                "size": 9,
            },
        ]
        adapter = _make_adapter(cmdj_map={"izj": string_entries})
        config = _make_config(tmp_path)
        config._typed_config = replace(
            config._typed_config,
            strings=StringsConfig(extract_ascii=True, extract_unicode=False),
        )
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.get_string_statistics()

        assert result["total_strings"] == 3
        assert result["avg_length"] > 0
        assert result["min_length"] >= 4
        assert result["max_length"] >= 4

    def test_get_string_statistics_empty(self, tmp_path):
        """Test statistics with no strings."""
        # No entries in cmdj_map means no strings extracted
        adapter = _make_adapter(cmdj_map={"izj": []})
        config = _make_config(tmp_path)
        config._typed_config = replace(
            config._typed_config,
            strings=StringsConfig(extract_ascii=True, extract_unicode=False),
        )
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.get_string_statistics()

        assert result["total_strings"] == 0
        assert result["avg_length"] == 0
        assert result["min_length"] == 0
        assert result["max_length"] == 0

    def test_get_string_statistics_with_charset(self, tmp_path):
        """Test statistics with charset analysis."""
        string_entries = [
            {
                "string": "test_str",
                "length": 8,
                "vaddr": 0x1000,
                "paddr": 0x400,
                "section": ".data",
                "type": "ascii",
                "size": 8,
            },
            {
                "string": "hello_world",
                "length": 11,
                "vaddr": 0x2000,
                "paddr": 0x500,
                "section": ".data",
                "type": "ascii",
                "size": 11,
            },
            {
                "string": "world_str",
                "length": 9,
                "vaddr": 0x3000,
                "paddr": 0x600,
                "section": ".data",
                "type": "ascii",
                "size": 9,
            },
        ]
        adapter = _make_adapter(cmdj_map={"izj": string_entries})
        config = _make_config(tmp_path)
        config._typed_config = replace(
            config._typed_config,
            strings=StringsConfig(extract_ascii=True, extract_unicode=False),
        )
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.get_string_statistics()

        assert "charset_analysis" in result
        assert "ascii" in result["charset_analysis"]


class TestCharsetAnalysis:
    """Test character set analysis."""

    def test_analyze_charset_ascii_only(self, tmp_path):
        """Test charset analysis with ASCII only."""
        adapter = _make_adapter()
        config = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, config)

        strings = ["test", "hello", "world"]
        result = analyzer._analyze_charset(strings)

        assert result["ascii"] == 3
        assert result["unicode"] == 0

    def test_analyze_charset_unicode(self, tmp_path):
        """Test charset analysis with Unicode."""
        adapter = _make_adapter()
        config = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, config)

        strings = ["test", "hello", "\u4e16\u754c"]  # ASCII + Unicode
        result = analyzer._analyze_charset(strings)

        assert result["ascii"] == 2
        assert result["unicode"] == 1

    def test_analyze_charset_printable(self, tmp_path):
        """Test charset analysis for printable strings."""
        adapter = _make_adapter()
        config = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, config)

        strings = ["test", "hello world"]
        result = analyzer._analyze_charset(strings)

        assert result["printable"] == 2

    def test_analyze_charset_alphanumeric(self, tmp_path):
        """Test charset analysis for alphanumeric strings."""
        adapter = _make_adapter()
        config = _make_config(tmp_path)
        analyzer = StringAnalyzer(adapter, config)

        strings = ["test123", "hello", "world!"]
        result = analyzer._analyze_charset(strings)

        # Only "test123" and "hello" are fully alphanumeric
        assert result["alphanumeric"] >= 1


class TestImportErrorScenarios:
    """Test behavior when extraction returns no useful data."""

    def test_extract_strings_empty_from_backend(self, tmp_path):
        """Test extraction when backend returns empty data."""
        adapter = _make_adapter(cmdj_map={"izj": []})
        config = _make_config(tmp_path)
        config._typed_config = replace(
            config._typed_config,
            strings=StringsConfig(extract_ascii=True, extract_unicode=False),
        )
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.extract_strings()

        assert isinstance(result, list)
        assert result == []

    def test_decode_strings_no_decodable(self, tmp_path):
        """Test decoding when no strings are decodable."""
        # Provide strings that are not valid base64 or hex
        string_entries = [
            {
                "string": "plain_text_string",
                "length": 17,
                "vaddr": 0x1000,
                "paddr": 0x400,
                "section": ".data",
                "type": "ascii",
                "size": 17,
            },
        ]
        adapter = _make_adapter(cmdj_map={"izj": string_entries})
        config = _make_config(tmp_path)
        config._typed_config = replace(
            config._typed_config,
            strings=StringsConfig(extract_ascii=True, extract_unicode=False),
        )
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.decode_strings()

        # No strings should be decoded since "plain_text_string" is not valid base64 or hex
        assert isinstance(result, list)


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_extract_strings_very_long_strings_filtered(self, tmp_path):
        """Test handling of very long strings (exceed max_length)."""
        long_string = "x" * 200
        string_entries = [
            {
                "string": long_string,
                "length": 200,
                "vaddr": 0x1000,
                "paddr": 0x400,
                "section": ".data",
                "type": "ascii",
                "size": 200,
            },
        ]
        adapter = _make_adapter(cmdj_map={"izj": string_entries})
        config = _make_config(tmp_path)
        config._typed_config = replace(
            config._typed_config,
            strings=StringsConfig(extract_ascii=True, extract_unicode=False, max_length=100),
        )
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.extract_strings()

        # The long string should be filtered out by filter_strings
        assert len(result) == 0

    def test_extract_strings_very_short_strings_filtered(self, tmp_path):
        """Test handling of very short strings (below min_length)."""
        string_entries = [
            {
                "string": "ab",
                "length": 2,
                "vaddr": 0x1000,
                "paddr": 0x400,
                "section": ".data",
                "type": "ascii",
                "size": 2,
            },
            {
                "string": "cd",
                "length": 2,
                "vaddr": 0x2000,
                "paddr": 0x500,
                "section": ".data",
                "type": "ascii",
                "size": 2,
            },
        ]
        adapter = _make_adapter(cmdj_map={"izj": string_entries})
        config = _make_config(tmp_path)
        config._typed_config = replace(
            config._typed_config,
            strings=StringsConfig(
                extract_ascii=True, extract_unicode=False, min_length=10, max_length=100
            ),
        )
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.extract_strings()

        assert len(result) == 0

    def test_extract_strings_empty_result(self, tmp_path):
        """Test extraction with empty result from both ASCII and Unicode."""
        adapter = _make_adapter(cmdj_map={"izj": [], "izuj": []})
        config = _make_config(tmp_path)
        config._typed_config = replace(
            config._typed_config,
            strings=StringsConfig(extract_ascii=True, extract_unicode=True),
        )
        analyzer = StringAnalyzer(adapter, config)

        result = analyzer.extract_strings()

        assert result == []
