#!/usr/bin/env python3
"""Branch-path tests for r2inspect/modules/string_analyzer.py."""

from __future__ import annotations

from typing import Any

from r2inspect.config import Config
from r2inspect.modules.string_analyzer import StringAnalyzer


class _StringEntriesAdapter:
    def __init__(
        self,
        ascii_entries: list[Any],
        unicode_entries: list[Any] | None = None,
    ):
        self.ascii_entries = ascii_entries
        self.unicode_entries = unicode_entries if unicode_entries is not None else []

    def cmdj(self, command: str) -> list[Any]:
        if command == "izj":
            return self.ascii_entries
        if command == "izuj":
            return self.unicode_entries
        return []


class _RaisingUnicodeStringAnalyzer(StringAnalyzer):
    """Hand-rolled subclass double whose unicode extraction raises."""

    def _extract_unicode_strings(self) -> list[str]:
        raise RuntimeError("extract error")


class _MalformedStringAnalyzer(StringAnalyzer):
    def extract_strings(self) -> list[str]:
        return ["ascii", None, 123, "ábc"]  # type: ignore[list-item]


def _config_with_overrides(overrides: dict[str, Any]) -> Config:
    cfg = Config()
    cfg.apply_overrides(overrides)
    return cfg


def test_string_analyzer_get_category_and_description():
    analyzer = StringAnalyzer(adapter=_StringEntriesAdapter([]), config=Config())
    assert analyzer.get_category() == "metadata"
    assert analyzer.get_description().startswith("Extracts and analyzes strings")


def test_extract_strings_limits_to_max_strings():
    adapter = _StringEntriesAdapter(
        [
            {"string": "alpha"},
            {"string": "bravo"},
            {"string": "charlie"},
        ]
    )
    config = _config_with_overrides({"general": {"max_strings": 1}})
    analyzer = StringAnalyzer(adapter=adapter, config=config)

    strings = analyzer.extract_strings()
    assert len(strings) == 1


def test_extract_strings_preserves_first_seen_order():
    adapter = _StringEntriesAdapter(
        [
            {"string": "bravo"},
            {"string": "alpha"},
            {"string": "bravo"},
        ]
    )
    config = _config_with_overrides({"general": {"max_strings": 10}})
    analyzer = StringAnalyzer(adapter=adapter, config=config)

    strings = analyzer.extract_strings()
    assert strings == ["bravo", "alpha"]


def test_extract_ascii_strings_exception_returns_empty():
    # A non-dict entry makes extract_strings_from_entries raise inside
    # _extract_ascii_strings, exercising its real except branch.
    analyzer = StringAnalyzer(adapter=_StringEntriesAdapter([123]), config=Config())
    assert analyzer._extract_ascii_strings() == []


def test_extract_unicode_strings_exception_returns_empty():
    analyzer = StringAnalyzer(
        adapter=_StringEntriesAdapter([], unicode_entries=[123]), config=Config()
    )
    assert analyzer._extract_unicode_strings() == []


def test_decode_strings_adds_base64_and_hex_results():
    adapter = _StringEntriesAdapter(
        [
            {"string": "QUJDRA=="},
            {"string": "41424344"},
        ]
    )
    analyzer = StringAnalyzer(adapter=adapter, config=Config())
    decoded = analyzer.decode_strings()

    assert {"original": "QUJDRA==", "decoded": "ABCD", "encoding": "base64"} in decoded
    assert {"original": "41424344", "decoded": "ABCD", "encoding": "hex"} in decoded


def test_get_string_statistics_counts_unicode_characters():
    adapter = _StringEntriesAdapter(
        [
            {"string": "ascii"},
            {"string": "ábcD"},
        ]
    )
    analyzer = StringAnalyzer(adapter=adapter, config=Config())
    stats = analyzer.get_string_statistics()
    assert stats["charset_analysis"]["unicode"] >= 1
    assert stats["charset_analysis"]["ascii"] >= 1


def test_get_string_statistics_skips_malformed_string_entries():
    analyzer = _MalformedStringAnalyzer(adapter=_StringEntriesAdapter([]), config=Config())
    stats = analyzer.get_string_statistics()
    assert stats["total_strings"] == 2
    assert stats["avg_length"] == 4.0
    assert stats["min_length"] == 3
    assert stats["max_length"] == 5
    assert stats["charset_analysis"]["ascii"] == 1
    assert stats["charset_analysis"]["unicode"] == 1


def test_extract_strings_exception_path_returns_partial_result():
    analyzer = _RaisingUnicodeStringAnalyzer(adapter=_StringEntriesAdapter([]), config=Config())
    strings = analyzer.extract_strings()
    assert isinstance(strings, list)
