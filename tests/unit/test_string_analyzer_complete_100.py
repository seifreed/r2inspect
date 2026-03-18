"""Comprehensive tests for string_analyzer.py - 100% coverage target."""

from __future__ import annotations

from r2inspect.modules.string_analyzer import StringAnalyzer


class DummyConfig:
    """Minimal config for StringAnalyzer tests."""

    def __init__(self) -> None:
        self.typed_config = type("Cfg", (), {})()
        self.typed_config.strings = type("Strings", (), {})()
        self.typed_config.general = type("General", (), {})()
        self.typed_config.strings.extract_ascii = True
        self.typed_config.strings.extract_unicode = True
        self.typed_config.strings.min_length = 3
        self.typed_config.strings.max_length = 256
        self.typed_config.general.max_strings = 1000


class StringTestAdapter:
    """Test adapter that provides the methods the command dispatch expects.

    ``get_strings_basic`` is called by the command dispatch for the ``izj``
    command.  For ``izuj`` (unicode strings) there is no mapped adapter method,
    so the dispatch falls through to ``cmdj`` on the r2 object -- which is this
    same adapter.
    """

    def __init__(
        self,
        *,
        strings_basic: list | None = None,
        strings_unicode: list | None = None,
    ) -> None:
        self._strings_basic = strings_basic if strings_basic is not None else []
        self._strings_unicode = strings_unicode if strings_unicode is not None else []

    def get_strings_basic(self) -> list:
        """Dispatched for ``izj`` (ASCII strings)."""
        return self._strings_basic

    def search_hex(self, pattern: str) -> str:
        return ""

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> list:
        """Fallback for commands not in the dispatch table (e.g. ``izuj``)."""
        if command == "izuj":
            return self._strings_unicode
        return []


def _make_analyzer(
    *,
    strings_basic: list | None = None,
    strings_unicode: list | None = None,
    extract_ascii: bool = True,
    extract_unicode: bool = True,
) -> StringAnalyzer:
    """Helper to create a StringAnalyzer with a test adapter."""
    adapter = StringTestAdapter(
        strings_basic=strings_basic,
        strings_unicode=strings_unicode,
    )
    config = DummyConfig()
    config.typed_config.strings.extract_ascii = extract_ascii
    config.typed_config.strings.extract_unicode = extract_unicode
    return StringAnalyzer(adapter=adapter, config=config)


def test_string_analyzer_init():
    """Test StringAnalyzer initialization with real objects."""
    analyzer = _make_analyzer()
    assert analyzer.min_length == 3
    assert analyzer.max_length == 256
    assert analyzer.max_strings == 1000


def test_string_analyzer_get_category():
    """Test get_category returns metadata."""
    analyzer = _make_analyzer()
    assert analyzer.get_category() == "metadata"


def test_string_analyzer_get_description():
    """Test get_description returns expected string."""
    analyzer = _make_analyzer()
    desc = analyzer.get_description()
    assert "strings" in desc.lower()


def test_string_analyzer_analyze_empty():
    """Test analyze with no strings returned."""
    analyzer = _make_analyzer()
    result = analyzer.analyze()
    assert result["total_strings"] == 0
    assert result["strings"] == []


def test_string_analyzer_analyze_with_strings():
    """Test analyze with strings returned from the adapter."""
    entries = [
        {"string": "HelloWorld", "vaddr": 4096, "size": 10, "type": "ascii"},
        {"string": "Test", "vaddr": 8192, "size": 4, "type": "ascii"},
    ]
    analyzer = _make_analyzer(strings_basic=entries)
    result = analyzer.analyze()
    assert result["total_strings"] >= 1
    assert isinstance(result["strings"], list)


def test_extract_strings_ascii_only():
    """Test extract_strings with only ASCII extraction."""
    entries = [
        {"string": "function_name", "vaddr": 100, "size": 13, "type": "ascii"},
    ]
    analyzer = _make_analyzer(strings_basic=entries, extract_unicode=False)
    strings = analyzer.extract_strings()
    assert isinstance(strings, list)


def test_extract_strings_unicode_only():
    """Test extract_strings with only Unicode extraction."""
    entries = [
        {"string": "wide_string", "vaddr": 200, "size": 11, "type": "wide"},
    ]
    analyzer = _make_analyzer(strings_unicode=entries, extract_ascii=False)
    strings = analyzer.extract_strings()
    assert isinstance(strings, list)


def test_extract_strings_both():
    """Test extract_strings with both ASCII and Unicode."""
    ascii_entries = [
        {"string": "ascii_str", "vaddr": 100, "size": 9, "type": "ascii"},
    ]
    unicode_entries = [
        {"string": "unicode_str", "vaddr": 200, "size": 11, "type": "wide"},
    ]
    analyzer = _make_analyzer(strings_basic=ascii_entries, strings_unicode=unicode_entries)
    strings = analyzer.extract_strings()
    assert isinstance(strings, list)


def test_extract_strings_error_handling():
    """Test extract_strings handles adapter errors gracefully."""

    class ErrorAdapter:
        def get_strings_basic(self):
            raise RuntimeError("adapter failure")

        def cmd(self, command):
            return ""

        def cmdj(self, command):
            return []

    config = DummyConfig()
    analyzer = StringAnalyzer(adapter=ErrorAdapter(), config=config)
    strings = analyzer.extract_strings()
    assert isinstance(strings, list)


def test_search_xor():
    """Test search_xor with a search string."""
    analyzer = _make_analyzer()
    result = analyzer.search_xor("AAAA")
    assert isinstance(result, list)


def test_get_suspicious_strings():
    """Test get_suspicious_strings returns list."""
    entries = [
        {"string": "CreateRemoteThread", "vaddr": 100, "size": 18, "type": "ascii"},
        {"string": "cmd.exe", "vaddr": 200, "size": 7, "type": "ascii"},
        {"string": "normal_string", "vaddr": 300, "size": 13, "type": "ascii"},
    ]
    analyzer = _make_analyzer(strings_basic=entries)
    suspicious = analyzer.get_suspicious_strings()
    assert isinstance(suspicious, list)


def test_decode_strings():
    """Test decode_strings returns decoded entries."""
    entries = [
        {"string": "SGVsbG8=", "vaddr": 100, "size": 8, "type": "ascii"},
        {"string": "normal", "vaddr": 200, "size": 6, "type": "ascii"},
    ]
    analyzer = _make_analyzer(strings_basic=entries)
    decoded = analyzer.decode_strings()
    assert isinstance(decoded, list)


def test_get_string_statistics():
    """Test get_string_statistics returns stats dict."""
    entries = [
        {"string": "hello", "vaddr": 100, "size": 5, "type": "ascii"},
        {"string": "world", "vaddr": 200, "size": 5, "type": "ascii"},
    ]
    analyzer = _make_analyzer(strings_basic=entries)
    stats = analyzer.get_string_statistics()
    assert "total_strings" in stats
    assert "avg_length" in stats
    assert "charset_analysis" in stats


def test_get_string_statistics_empty():
    """Test get_string_statistics with no strings."""
    analyzer = _make_analyzer()
    stats = analyzer.get_string_statistics()
    assert stats["total_strings"] == 0
    assert stats["avg_length"] == 0


def test_analyze_charset():
    """Test _analyze_charset categorizes strings correctly."""
    analyzer = _make_analyzer()
    charset = analyzer._analyze_charset(["hello", "world123", "abc"])
    assert charset["ascii"] == 3
    assert charset["printable"] == 3


def test_analyze_charset_empty():
    """Test _analyze_charset with empty list."""
    analyzer = _make_analyzer()
    charset = analyzer._analyze_charset([])
    assert charset["ascii"] == 0
    assert charset["unicode"] == 0
