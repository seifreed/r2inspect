"""Branch-path tests for r2inspect/modules/string_analyzer.py."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from r2inspect.config import Config
from r2inspect.modules.string_analyzer import StringAnalyzer
from r2inspect.modules.string_domain import decode_base64, decode_hex


# ---------------------------------------------------------------------------
# Stub helpers
# ---------------------------------------------------------------------------


class _StringsConfig:
    min_length: int = 4
    max_length: int = 100
    extract_ascii: bool = True
    extract_unicode: bool = True


class _GeneralConfig:
    max_strings: int = 3


class _TypedConfig:
    strings = _StringsConfig()
    general = _GeneralConfig()


class StubConfig:
    typed_config = _TypedConfig()


class StubAdapter:
    """Returns predefined string entries for izj/izuj; no real r2 needed."""

    def __init__(self, strings_basic: list | None = None) -> None:
        self._strings_basic = strings_basic or []

    def get_strings_basic(self) -> list[dict[str, Any]]:
        return self._strings_basic

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b""


class FailingStringsAdapter:
    """Adapter whose get_strings_basic() raises so we hit the except path."""

    def get_strings_basic(self) -> list[dict[str, Any]]:
        raise RuntimeError("simulated strings failure")

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_analyzer(adapter: Any = None, config: Any = None) -> StringAnalyzer:
    if adapter is None:
        adapter = StubAdapter()
    if config is None:
        config = StubConfig()
    return StringAnalyzer(adapter=adapter, config=config)


# ---------------------------------------------------------------------------
# extract_strings - max_strings truncation (line 81)
# ---------------------------------------------------------------------------


def test_extract_strings_truncates_to_max_strings():
    entries = [
        {"string": f"hello_world_{i}", "length": 12} for i in range(10)
    ]
    config = StubConfig()
    adapter = StubAdapter(strings_basic=entries)
    analyzer = StringAnalyzer(adapter=adapter, config=config)
    strings = analyzer.extract_strings()
    assert len(strings) <= config.typed_config.general.max_strings


# ---------------------------------------------------------------------------
# _extract_ascii_strings exception path (lines 93-95)
# ---------------------------------------------------------------------------


def test_extract_ascii_strings_returns_empty_on_adapter_failure():
    analyzer = make_analyzer(adapter=FailingStringsAdapter())
    result = analyzer._extract_ascii_strings()
    assert result == []


# ---------------------------------------------------------------------------
# search_xor method (lines 112-121)
# ---------------------------------------------------------------------------


def test_search_xor_returns_list_on_real_adapter():
    adapter = StubAdapter()
    analyzer = make_analyzer(adapter=adapter)
    result = analyzer.search_xor("test")
    assert isinstance(result, list)


def test_search_xor_with_empty_string_returns_list():
    adapter = StubAdapter()
    analyzer = make_analyzer(adapter=adapter)
    result = analyzer.search_xor("")
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# decode_strings method (lines 130-142)
# ---------------------------------------------------------------------------


def test_decode_strings_returns_list():
    entries = [
        {"string": "aGVsbG8=", "length": 8},   # base64 "hello"
        {"string": "68656c6c6f", "length": 10}, # hex "hello"
        {"string": "plain_text_string", "length": 17},
    ]
    adapter = StubAdapter(strings_basic=entries)
    analyzer = make_analyzer(adapter=adapter)
    result = analyzer.decode_strings()
    assert isinstance(result, list)


def test_decode_strings_decodes_base64_entry():
    entries = [{"string": "aGVsbG8=", "length": 8}]
    adapter = StubAdapter(strings_basic=entries)
    analyzer = make_analyzer(adapter=adapter)
    result = analyzer.decode_strings()
    encoded_results = [r for r in result if r.get("encoding") == "base64"]
    assert len(encoded_results) >= 1


def test_decode_strings_decodes_hex_entry():
    entries = [{"string": "68656c6c6f", "length": 10}]
    adapter = StubAdapter(strings_basic=entries)
    analyzer = make_analyzer(adapter=adapter)
    result = analyzer.decode_strings()
    hex_results = [r for r in result if r.get("encoding") == "hex"]
    assert len(hex_results) >= 1


def test_decode_strings_with_no_encoded_strings():
    entries = [{"string": "plain_text_only", "length": 15}]
    adapter = StubAdapter(strings_basic=entries)
    analyzer = make_analyzer(adapter=adapter)
    result = analyzer.decode_strings()
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# _decode_base64 and _decode_hex delegate methods (lines 146, 150)
# ---------------------------------------------------------------------------


def test_decode_base64_helper_returns_dict_for_valid_base64():
    analyzer = make_analyzer()
    result = analyzer._decode_base64("aGVsbG8=")
    assert result is not None
    assert result.get("encoding") == "base64"


def test_decode_base64_helper_returns_none_for_non_base64():
    analyzer = make_analyzer()
    result = analyzer._decode_base64("not_b64!!!")
    assert result is None


def test_decode_hex_helper_returns_dict_for_valid_hex():
    analyzer = make_analyzer()
    result = analyzer._decode_hex("68656c6c6f")
    assert result is not None
    assert result.get("encoding") == "hex"


def test_decode_hex_helper_returns_none_for_non_hex():
    analyzer = make_analyzer()
    result = analyzer._decode_hex("not hex at all")
    assert result is None


# ---------------------------------------------------------------------------
# _analyze_charset with unicode strings (line 174)
# ---------------------------------------------------------------------------


def test_analyze_charset_counts_unicode_strings():
    analyzer = make_analyzer()
    strings = ["hello", "caf\u00e9", "na\u00efve"]
    stats = analyzer._analyze_charset(strings)
    assert stats["unicode"] >= 2
    assert stats["ascii"] >= 1


def test_analyze_charset_all_ascii():
    analyzer = make_analyzer()
    strings = ["hello", "world", "test"]
    stats = analyzer._analyze_charset(strings)
    assert stats["ascii"] == 3
    assert stats["unicode"] == 0


def test_analyze_charset_empty_list():
    analyzer = make_analyzer()
    stats = analyzer._analyze_charset([])
    assert stats["ascii"] == 0
    assert stats["unicode"] == 0


def test_analyze_charset_printable_and_alphanumeric():
    analyzer = make_analyzer()
    strings = ["Hello123", "hello world"]
    stats = analyzer._analyze_charset(strings)
    assert stats["alphanumeric"] >= 1
    assert stats["printable"] >= 1


# ---------------------------------------------------------------------------
# get_suspicious_strings and get_string_statistics
# ---------------------------------------------------------------------------


def test_get_suspicious_strings_returns_list():
    adapter = StubAdapter(strings_basic=[
        {"string": "cmd.exe", "length": 7},
        {"string": "http://evil.com", "length": 15},
    ])
    analyzer = make_analyzer(adapter=adapter)
    result = analyzer.get_suspicious_strings()
    assert isinstance(result, list)


def test_get_string_statistics_returns_expected_keys():
    adapter = StubAdapter(strings_basic=[
        {"string": "hello_world", "length": 11},
        {"string": "another_str", "length": 11},
    ])
    analyzer = make_analyzer(adapter=adapter)
    stats = analyzer.get_string_statistics()
    assert "total_strings" in stats
    assert "avg_length" in stats
    assert "min_length" in stats
    assert "max_length" in stats
    assert "charset_analysis" in stats


def test_get_string_statistics_with_no_strings():
    adapter = StubAdapter(strings_basic=[])
    analyzer = make_analyzer(adapter=adapter)
    stats = analyzer.get_string_statistics()
    assert stats["total_strings"] == 0
    assert stats["avg_length"] == 0
