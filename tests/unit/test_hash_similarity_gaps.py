"""Coverage gap tests for rich_header_analyzer and yara_rules_support.

No mocks, no monkeypatch: each path is driven by real input or a hand-rolled
RichHeaderAnalyzer subclass that overrides the extraction hooks under test.

Covers:
  rich_header_analyzer.py        – the pefile-absent and r2pipe extraction paths
  yara_rules_support.py          – the outer except in list_available_rules
"""

from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.infrastructure.logging import get_logger
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer
from r2inspect.modules.yara_rules_support import (
    discover_rule_files,
    list_available_rules,
    process_matches,
)

# ---------------------------------------------------------------------------
# rich_header_analyzer.py – _extract_rich_header_pefile on a real PE
#
# hello_pe.exe is a minimal real PE with no Rich Header, so the pefile path
# returns None via the _pefile_has_rich_header guard.  Real input, no mock
# (the previous version patched rich_header_analyzer.pefile, but the pefile
# branch lives in rich_header_pefile.py with its own import, so the patch
# never took effect and the asserted success path never executed).
# ---------------------------------------------------------------------------


def test_extract_rich_header_pefile_no_rich_header_returns_none() -> None:
    analyzer = RichHeaderAnalyzer(filepath="samples/fixtures/hello_pe.exe")
    assert analyzer._extract_rich_header_pefile() is None


# ---------------------------------------------------------------------------
# rich_header_analyzer.py – lines 350-355
#
# The success path inside _try_rich_dans_combinations when both offsets are
# valid AND _try_extract_rich_at_offsets returns data.
# We use a subclass that overrides _try_extract_rich_at_offsets.
# ---------------------------------------------------------------------------


class _SuccessExtractionRHA(RichHeaderAnalyzer):
    def _try_extract_rich_at_offsets(
        self, dans_offset: int, rich_offset: int
    ) -> dict[str, object] | None:
        return {"xor_key": 0xDEAD, "entries": [], "checksum": 0xDEAD}


def test_try_rich_dans_combinations_success_path() -> None:
    """Lines 350-355: valid offsets + successful extraction returns rich data."""
    analyzer = _SuccessExtractionRHA(adapter=None, filepath=None)
    # dans_offset=0x20 < rich_offset=0x60; difference=0x40 ≤ 1024 → valid
    result = analyzer._try_rich_dans_combinations([{"offset": 0x60}], [{"offset": 0x20}])
    assert result == {"xor_key": 0xDEAD, "entries": [], "checksum": 0xDEAD}


def test_try_rich_dans_combinations_calls_extraction_on_valid_offsets() -> None:
    """Line 350: _try_extract_rich_at_offsets is called when offsets are valid."""
    calls: list[tuple[int, int]] = []

    class _TrackingRHA(RichHeaderAnalyzer):
        def _try_extract_rich_at_offsets(
            self, dans_offset: int, rich_offset: int
        ) -> dict[str, object] | None:
            calls.append((dans_offset, rich_offset))
            return None

    analyzer = _TrackingRHA(adapter=None, filepath=None)
    result = analyzer._try_rich_dans_combinations([{"offset": 0x80}], [{"offset": 0x10}])
    assert result is None
    assert len(calls) == 1
    assert calls[0] == (0x10, 0x80)


# ---------------------------------------------------------------------------
# rich_header_analyzer.py – line 307
#
# return rich_data inside _extract_rich_header when _try_rich_dans_combinations
# succeeds.  We use a subclass that:
#   • overrides _direct_file_rich_search → returns None (force r2pipe path)
#   • overrides _collect_rich_dans_offsets → returns valid offset dicts
#   • overrides _try_extract_rich_at_offsets → returns fake data
# ---------------------------------------------------------------------------


class _FullPipeRHA(RichHeaderAnalyzer):
    def _direct_file_rich_search(self) -> dict[str, object] | None:
        return None  # force the r2pipe branch

    def _collect_rich_dans_offsets(
        self,
    ) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        return [{"offset": 0x60}], [{"offset": 0x20}]

    def _try_extract_rich_at_offsets(
        self, dans_offset: int, rich_offset: int
    ) -> dict[str, object] | None:
        return {"xor_key": 0, "entries": [], "checksum": 0}


def test_extract_rich_header_returns_data_via_r2pipe_path() -> None:
    """Line 307: _extract_rich_header returns rich_data from _try_rich_dans_combinations."""
    analyzer = _FullPipeRHA(adapter=None, filepath=None)
    result = analyzer._extract_rich_header()
    assert result == {"xor_key": 0, "entries": [], "checksum": 0}


# ---------------------------------------------------------------------------
# yara_rules_support.list_available_rules – outer exception path
#
# list_available_rules() wraps its body in a defensive try/except that returns
# the (empty) accumulator on any unexpected error.  A non-relative glob pattern
# makes Path.rglob raise NotImplementedError, which the outer except swallows.
# This exercises that path with a real input — no monkeypatch.
# ---------------------------------------------------------------------------


def test_list_available_rules_outer_exception_returns_empty(tmp_path: Path) -> None:
    """Invalid glob patterns should surface instead of being swallowed."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    with pytest.raises(NotImplementedError):
        list_available_rules(str(rules_dir), ["/abs"], get_logger(__name__))


def test_process_matches_non_list_returns_empty() -> None:
    """Non-list YARA match input is ignored instead of raising."""
    assert process_matches(None, get_logger(__name__)) == []


def test_process_matches_accepts_iterable_nested_fields() -> None:
    class Instance:
        def __init__(self) -> None:
            self.offset = 7
            self.matched_data = b"abc"
            self.length = 3

    class StringMatch:
        def __init__(self) -> None:
            self.identifier = "$a"
            self.instances = (Instance(),)

    class Match:
        def __init__(self) -> None:
            self.rule = "Demo"
            self.namespace = "default"
            self.tags = ("tag1",)
            self.meta = {"key": "value"}
            self.strings = (StringMatch(),)

    result = process_matches([Match()], get_logger(__name__))
    assert result[0]["tags"] == ["tag1"]
    assert result[0]["strings"][0]["instances"][0]["matched_data"] == "abc"


def test_discover_rule_files_non_list_patterns_returns_empty(tmp_path: Path) -> None:
    """Invalid YARA glob input is ignored instead of raising."""
    assert discover_rule_files(tmp_path, None) == []


def test_discover_rule_files_normalizes_iterable_patterns(tmp_path: Path) -> None:
    (tmp_path / "one.yar").write_text("rule a { condition: true }")
    (tmp_path / "two.yara").write_text("rule b { condition: true }")

    patterns = (pattern for pattern in ["*.yar", "*.yara", ""])

    result = discover_rule_files(tmp_path, patterns)
    assert {path.name for path in result} == {"one.yar", "two.yara"}


def test_list_available_rules_normalizes_iterable_patterns(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "one.yar").write_text("rule a { condition: true }")
    logger = get_logger(__name__)

    patterns = (pattern for pattern in ["*.yar", "*.yara"])
    result = list_available_rules(str(rules_dir), patterns, logger)

    assert [item["name"] for item in result] == ["one.yar"]
