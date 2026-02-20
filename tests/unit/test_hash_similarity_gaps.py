"""Coverage gap tests for ssdeep_analyzer, rich_header_analyzer, yara_analyzer.

No unittest.mock / MagicMock / patch.  Module-level attribute monkey-patching is used
where the real execution path cannot be triggered by input alone.  Every monkey-patch
is restored in a finally block so tests remain isolated.

Covers:
  ssdeep_analyzer.py  – lines 76-77, 86, 151, 250-251
  rich_header_analyzer.py – lines 33-35 (UNREACHABLE, pefile installed – noted below),
                             145-151, 307, 350-355
  yara_analyzer.py    – lines 415-416
  Lines 265-266 (SIGALRM timeout path) are unreachable from pytest because compilation
  never actually times out; noted and skipped.
"""

from __future__ import annotations

import os
import subprocess
import tempfile

import pytest
import ssdeep as ssdeep_lib

import r2inspect.modules.rich_header_analyzer as rha_mod
import r2inspect.modules.ssdeep_analyzer as ssdeep_mod
import r2inspect.modules.yara_analyzer as yara_mod
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer
from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer
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
# ssdeep_analyzer.py – lines 76-77
#
# Triggered when ssdeep_module.hash(file_content) raises a *non-OSError* exception.
# The outer "except Exception as e" block at line 76 catches it, logs a warning (77),
# and falls through to the binary fallback.  We arrange for the binary path to also
# fail (by using a subclass that has no binary) so the full flow completes cleanly.
# ---------------------------------------------------------------------------


class _NoBinarySSDeep(SSDeepAnalyzer):
    """Subclass where the ssdeep binary is always absent."""

    @staticmethod
    def _resolve_ssdeep_binary() -> str | None:
        return None


class _RaisingHashSsdeep:
    """Fake ssdeep module whose hash() raises a RuntimeError (not OSError)."""

    def hash(self, data: bytes) -> str:
        raise RuntimeError("fake ssdeep failure for line 76-77")

    def hash_from_file(self, path: str) -> str:
        raise RuntimeError("fake ssdeep failure for line 76-77")

    def compare(self, h1: str, h2: str) -> int:
        raise RuntimeError("fake compare failure")


def test_calculate_hash_outer_except_branch(tmp_path: object) -> None:
    """Lines 76-77: outer except in _calculate_hash fires when ssdeep.hash() raises."""
    target = tmp_path / "sample.bin"  # type: ignore[operator]
    target.write_bytes(b"A" * 512)

    orig = ssdeep_mod.get_ssdeep
    ssdeep_mod.get_ssdeep = lambda: _RaisingHashSsdeep()
    try:
        analyzer = _NoBinarySSDeep(str(target))
        h, method, err = analyzer._calculate_hash()
        # hash is None (no library, no binary), error message from binary path
        assert h is None
        assert err is not None
    finally:
        ssdeep_mod.get_ssdeep = orig


# ---------------------------------------------------------------------------
# ssdeep_analyzer.py – line 86
#
# Triggered when _calculate_with_binary() succeeds but returns a falsy hash.
# We use a subclass that overrides _calculate_with_binary to return (None, …),
# while the library is suppressed so the binary fallback is actually invoked.
# ---------------------------------------------------------------------------


class _NullHashBinarySSDeep(SSDeepAnalyzer):
    """Subclass whose binary path always returns a None hash."""

    def _calculate_with_binary(self) -> tuple[str | None, str]:
        return None, "system_binary"


def test_calculate_hash_binary_returns_no_hash(tmp_path: object) -> None:
    """Line 86: 'SSDeep binary calculation returned no hash' path."""
    target = tmp_path / "sample.bin"  # type: ignore[operator]
    target.write_bytes(b"B" * 512)

    orig = ssdeep_mod.get_ssdeep
    ssdeep_mod.get_ssdeep = lambda: None
    try:
        analyzer = _NullHashBinarySSDeep(str(target))
        h, method, err = analyzer._calculate_hash()
        assert h is None
        assert err == "SSDeep binary calculation returned no hash"
    finally:
        ssdeep_mod.get_ssdeep = orig


# ---------------------------------------------------------------------------
# ssdeep_analyzer.py – line 151
#
# Triggered when subprocess.run() raises subprocess.SubprocessError inside
# _calculate_with_binary.  We replace ssdeep_mod.subprocess with a minimal
# fake object that raises on .run() while still exposing the exception classes.
# ---------------------------------------------------------------------------


class _SubprocessErrorSubprocess:
    """Fake subprocess module whose .run() raises SubprocessError."""

    SubprocessError = subprocess.SubprocessError
    TimeoutExpired = subprocess.TimeoutExpired

    @staticmethod
    def run(*args: object, **kwargs: object) -> object:
        raise subprocess.SubprocessError("injected SubprocessError for line 151")


def test_calculate_with_binary_subprocess_error(tmp_path: object) -> None:
    """Line 151: SubprocessError in _calculate_with_binary is re-raised as RuntimeError."""
    target = tmp_path / "sample.bin"  # type: ignore[operator]
    target.write_bytes(b"C" * 512)

    orig_subprocess = ssdeep_mod.subprocess
    ssdeep_mod.subprocess = _SubprocessErrorSubprocess()
    try:
        analyzer = SSDeepAnalyzer(str(target))
        with pytest.raises(RuntimeError, match="ssdeep subprocess error"):
            analyzer._calculate_with_binary()
    finally:
        ssdeep_mod.subprocess = orig_subprocess


# ---------------------------------------------------------------------------
# ssdeep_analyzer.py – lines 250-251
#
# Triggered when temp_dir.cleanup() raises inside the finally block of
# _compare_with_binary.  We replace tempfile.TemporaryDirectory (on the
# ssdeep_mod.tempfile namespace, which IS the real tempfile module) with a
# wrapper class whose cleanup() succeeds then raises.
#
# IMPORTANT: we save the real class *before* patching so the wrapper's
# __init__ can call the original without infinite recursion.
# ---------------------------------------------------------------------------

_real_TemporaryDirectory = tempfile.TemporaryDirectory  # captured before any patching


class _FailCleanupTempDir:
    """Wrapper around the real TemporaryDirectory whose cleanup() raises."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        self._real = _real_TemporaryDirectory(*args, **kwargs)
        self.name = self._real.name

    def cleanup(self) -> None:
        self._real.cleanup()
        raise RuntimeError("deliberate cleanup failure for lines 250-251")


def test_compare_with_binary_cleanup_exception() -> None:
    """Lines 250-251: exception from temp_dir.cleanup() is caught and logged."""
    # Create a real ssdeep hash to compare
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"D" * 512)
        fname = f.name
    try:
        h = ssdeep_lib.hash_from_file(fname)
    finally:
        os.unlink(fname)

    orig_tmpdir = ssdeep_mod.tempfile.TemporaryDirectory
    ssdeep_mod.tempfile.TemporaryDirectory = _FailCleanupTempDir
    try:
        # Result may be None or an int – the important thing is that the
        # cleanup exception is swallowed, not re-raised.
        result = SSDeepAnalyzer._compare_with_binary(h, h)
        assert result is None or isinstance(result, int)
    finally:
        ssdeep_mod.tempfile.TemporaryDirectory = orig_tmpdir


# ---------------------------------------------------------------------------
# rich_header_analyzer.py – lines 33-35  (UNREACHABLE)
#
# These lines form the "except ImportError" fallback for pefile.  Since pefile
# IS installed in this environment, the ImportError branch can never be reached
# at module import time.  No test is written for these lines.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# rich_header_analyzer.py – lines 145-151
#
# The success path inside _extract_rich_header_pefile when pefile loads a PE
# that has a RICH_HEADER and can produce a rich hash.  We monkey-patch
# rha_mod.pefile with a minimal fake module so no real PE file is needed.
# ---------------------------------------------------------------------------


class _FakeRichHeader:
    checksum = 0x12345678
    clear_data = bytes(range(8))  # 8 bytes – valid for parse_clear_data_entries
    values: list[object] = []  # empty → _pefile_extract_entries returns []
    #                            → line 148 branch → _pefile_entries_from_clear_data called


class _FakePEInstance:
    RICH_HEADER = _FakeRichHeader()

    def get_rich_header_hash(self) -> str:
        return "deadbeef01020304"

    def close(self) -> None:
        pass


class _FakePefileModule:
    @staticmethod
    def PE(filepath: str, **kwargs: object) -> _FakePEInstance:
        return _FakePEInstance()


def test_extract_rich_header_pefile_success_path(tmp_path: object) -> None:
    """Lines 145-151: pefile finds RICH_HEADER and calculates hash successfully."""
    pe_file = tmp_path / "fake.exe"  # type: ignore[operator]
    pe_file.write_bytes(b"MZ" + b"\x00" * 62)

    orig_pefile = rha_mod.pefile
    orig_available = rha_mod.PEFILE_AVAILABLE
    rha_mod.pefile = _FakePefileModule()  # type: ignore[assignment]
    rha_mod.PEFILE_AVAILABLE = True
    try:
        analyzer = RichHeaderAnalyzer(filepath=str(pe_file))
        result = analyzer._extract_rich_header_pefile()
        assert result is not None
        assert result.get("richpe_hash") == "deadbeef01020304"
        assert result.get("xor_key") == 0x12345678
    finally:
        rha_mod.pefile = orig_pefile
        rha_mod.PEFILE_AVAILABLE = orig_available


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
#
# Lines 265-266 (SIGALRM / TimeoutException in _compile_sources_with_timeout)
# are unreachable from pytest: YARA compilation of small rule sets completes
# in microseconds, never reaching the 30-second alarm.  These lines are skipped.
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
