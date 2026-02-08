from r2inspect.modules import search_helpers, string_analyzer, string_extraction


class DummyConfig:
    def __init__(self):
        self.typed_config = type("Cfg", (), {})()
        self.typed_config.strings = type("Strings", (), {})()
        self.typed_config.general = type("General", (), {})()
        self.typed_config.strings.extract_ascii = True
        self.typed_config.strings.extract_unicode = True
        self.typed_config.strings.min_length = 3
        self.typed_config.strings.max_length = 10
        self.typed_config.general.max_strings = 10


class DummyAdapter:
    def get_strings_basic(self):
        return [{"string": "abc"}, {"string": "de"}]

    def get_strings(self):
        return [{"string": "unicode"}]

    def search_hex(self, pattern: str):
        return "0x1"

    def search_text(self, pattern: str):
        return f"match:{pattern}"


class DummyLogger:
    def __getattr__(self, _name):
        return lambda *args, **kwargs: None


def test_string_extraction_helpers():
    entries = [{"string": "abcd"}, {"string": "a"}]
    assert string_extraction.extract_strings_from_entries(entries, 3) == ["abcd"]

    ascii_strings = string_extraction.extract_ascii_from_bytes([65, 66, 0, 67], min_length=2)
    assert ascii_strings == ["AB"]

    parts = string_extraction.split_null_terminated("abc\0def", min_length=2)
    assert parts == ["abc", "def"]


def test_search_helpers():
    adapter = DummyAdapter()
    assert search_helpers.search_text(adapter, None, " a ") == "match:a"
    assert search_helpers.search_hex(adapter, None, " ff ") == "0x1"


def test_string_analyzer_flow():
    analyzer = string_analyzer.StringAnalyzer(DummyAdapter(), DummyConfig())

    result = analyzer.analyze()
    assert result["available"] is True
    assert result["total_strings"] > 0

    strings = analyzer.extract_strings()
    assert "abc" in strings

    suspicious = analyzer.get_suspicious_strings()
    assert isinstance(suspicious, list)

    decoded = analyzer.decode_strings()
    assert isinstance(decoded, list)

    stats = analyzer.get_string_statistics()
    assert stats["total_strings"] == len(strings)

    assert analyzer._decode_base64("QUJDRA==")
    assert analyzer._decode_hex("4142")

    xor_matches = analyzer.search_xor("A")
    assert xor_matches
