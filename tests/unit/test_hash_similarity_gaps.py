"""Coverage gap tests for rich_header_analyzer and yara_analyzer.

No the stdlib mock library / mock objects / patch.  Module-level attribute monkey-patching is used
where the real execution path cannot be triggered by input alone.  Every monkey-patch
is restored in a finally block so tests remain isolated.

Covers:
  rich_header_analyzer.py – lines 145-151, 307, 350-355
  yara_analyzer.py    – lines 415-416
"""

from __future__ import annotations

import r2inspect.modules.yara_analyzer as yara_mod
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer
from r2inspect.modules.yara_analyzer import YaraAnalyzer

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


class _FakeConfig:
    def __init__(self, path: str) -> None:
        self._path = path

    def get_yara_rules_path(self) -> str:
        return self._path


class _FakeAdapter:
    pass


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
# yara_analyzer.py – lines 415-416
#
# Triggered when an unexpected exception escapes the try block inside
# list_available_rules().  We replace yara_mod.os with a thin facade whose
# path.isfile() raises, causing the outer except to fire.
# ---------------------------------------------------------------------------

_real_os = __import__("os")  # reference to the real os module


class _FakeOsPath:
    @staticmethod
    def exists(p: str) -> bool:
        return True  # pass the early-return guard

    @staticmethod
    def isfile(p: str) -> bool:
        raise RuntimeError("injected error to trigger lines 415-416")

    @staticmethod
    def isdir(p: str) -> bool:
        return _real_os.path.isdir(p)


class _FakeOs:
    path = _FakeOsPath()
    stat = staticmethod(_real_os.stat)


def test_list_available_rules_outer_exception_path(tmp_path: object) -> None:
    """Lines 415-416: outer except in list_available_rules catches RuntimeError."""
    rules_dir = tmp_path / "rules"  # type: ignore[operator]
    rules_dir.mkdir()
    config = _FakeConfig(str(rules_dir))
    analyzer = YaraAnalyzer(_FakeAdapter(), config=config)

    orig_os = yara_mod.os
    yara_mod.os = _FakeOs()  # type: ignore[assignment]
    try:
        result = analyzer.list_available_rules("/tmp")
        # Exception was swallowed; result is an empty list
        assert result == []
    finally:
        yara_mod.os = orig_os
