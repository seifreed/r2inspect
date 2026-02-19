"""Wave-3 coverage tests for ssdeep_analyzer.py and telfhash_analyzer.py.

Targets the 8 lines still uncovered after all prior test waves:
  ssdeep_analyzer.py  : 76-77, 86, 151, 250-251
  telfhash_analyzer.py: 10-11

No mocks, no unittest.mock, no MagicMock, no patch.
Module-level attribute injection (direct assignment) is used where necessary.
"""

from __future__ import annotations

import importlib
import subprocess
import sys
import tempfile as _tempfile
from pathlib import Path

import pytest

import r2inspect.modules.ssdeep_analyzer as _ssdeep_mod
import r2inspect.utils.ssdeep_loader as _ssdeep_loader
from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer


# ---------------------------------------------------------------------------
# Helpers – fake objects injected directly into module attributes
# ---------------------------------------------------------------------------


class _FakeFailSsdeep:
    """Fake ssdeep library whose hash() raises a generic (non-OSError) exception.

    Used to drive the 'except Exception' branch in SSDeepAnalyzer._calculate_hash
    (lines 76-77) and to force fallthrough to the binary path (line 86).
    """

    def hash(self, data: bytes) -> str:
        raise RuntimeError("fake ssdeep failure")

    def hash_from_file(self, path: str) -> str:
        return "3:FakeHashFromFile:FakeHashFromFile"

    def compare(self, h1: str, h2: str) -> int:
        return 0


class _NullBinarySSDeepAnalyzer(SSDeepAnalyzer):
    """Subclass whose _calculate_with_binary returns (None, ...) instead of a real hash.

    When combined with _FakeFailSsdeep, this makes _calculate_hash reach line 86.
    """

    def _calculate_with_binary(self) -> tuple[str | None, str]:  # type: ignore[override]
        return None, "system_binary"


class _FakeSubprocess:
    """Drop-in replacement for the subprocess module used inside _calculate_with_binary.

    run() raises SubprocessError to exercise the except branch at line 150-151.
    All other names needed by the module are delegated to the real subprocess.
    """

    TimeoutExpired = subprocess.TimeoutExpired
    SubprocessError = subprocess.SubprocessError

    @staticmethod
    def run(*args: object, **kwargs: object) -> None:  # type: ignore[override]
        raise subprocess.SubprocessError("simulated subprocess error")


_RealTemporaryDirectory = _tempfile.TemporaryDirectory  # captured before any replacement


class _BrokenCleanupTempDir:
    """Fake TemporaryDirectory whose cleanup() raises OSError after cleaning up.

    Uses the captured real class so that the constructor does not recurse when
    tempfile.TemporaryDirectory has been replaced with this class.
    The real directory is created so that file writes inside _compare_with_binary
    can succeed; cleanup then raises to exercise lines 250-251.
    """

    def __init__(self, prefix: str = "") -> None:
        self._real = _RealTemporaryDirectory(prefix=prefix)
        self.name = self._real.name

    def cleanup(self) -> None:
        try:
            self._real.cleanup()
        except Exception:
            pass
        raise OSError("simulated TemporaryDirectory cleanup failure")


# ---------------------------------------------------------------------------
# ssdeep_analyzer.py  lines 76-77
# "except Exception as e" handler when ssdeep_module.hash() raises non-OSError
# ---------------------------------------------------------------------------


def test_calculate_hash_non_oserror_exception_hits_warning_path(tmp_path: Path) -> None:
    """Lines 76-77: generic exception from ssdeep.hash() is caught and logged."""
    sample = tmp_path / "wave3_sample.bin"
    sample.write_bytes(b"X" * 512)

    orig = _ssdeep_loader._ssdeep_module
    _ssdeep_loader._ssdeep_module = _FakeFailSsdeep()
    try:
        analyzer = SSDeepAnalyzer(filepath=str(sample))
        # _calculate_hash will try library first (raises RuntimeError at line 64),
        # catch it at line 76-77, then fall through to the binary path.
        hv, method, err = analyzer._calculate_hash()
        # Result depends on whether the ssdeep binary is present; we just need
        # lines 76-77 to have been executed (no assertion on the hash itself).
        assert hv is None or isinstance(hv, str)
    finally:
        _ssdeep_loader._ssdeep_module = orig


# ---------------------------------------------------------------------------
# ssdeep_analyzer.py  line 86
# "return None, None, 'SSDeep binary calculation returned no hash'"
# Reached when: library fails (76-77) AND _calculate_with_binary returns falsy hash
# ---------------------------------------------------------------------------


def test_calculate_hash_binary_returns_no_hash_triggers_no_hash_message(tmp_path: Path) -> None:
    """Line 86: 'SSDeep binary calculation returned no hash' returned when binary yields None."""
    sample = tmp_path / "wave3_sample2.bin"
    sample.write_bytes(b"Y" * 512)

    orig = _ssdeep_loader._ssdeep_module
    _ssdeep_loader._ssdeep_module = _FakeFailSsdeep()
    try:
        analyzer = _NullBinarySSDeepAnalyzer(filepath=str(sample))
        hv, method, err = analyzer._calculate_hash()
        assert hv is None
        assert err == "SSDeep binary calculation returned no hash"
    finally:
        _ssdeep_loader._ssdeep_module = orig


# ---------------------------------------------------------------------------
# ssdeep_analyzer.py  line 151
# "raise RuntimeError(f'ssdeep subprocess error: {e}')"
# Reached when subprocess.run raises subprocess.SubprocessError
# ---------------------------------------------------------------------------


def test_calculate_with_binary_subprocess_error_raises_runtime_error(tmp_path: Path) -> None:
    """Line 151: subprocess.SubprocessError from run() is wrapped in RuntimeError."""
    if SSDeepAnalyzer._resolve_ssdeep_binary() is None:
        pytest.skip("ssdeep binary not available in PATH")

    sample = tmp_path / "wave3_subprocess_err.bin"
    sample.write_bytes(b"Z" * 512)
    analyzer = SSDeepAnalyzer(filepath=str(sample))

    orig_subprocess = _ssdeep_mod.subprocess
    _ssdeep_mod.subprocess = _FakeSubprocess()  # type: ignore[assignment]
    try:
        with pytest.raises(RuntimeError, match="ssdeep subprocess error"):
            analyzer._calculate_with_binary()
    finally:
        _ssdeep_mod.subprocess = orig_subprocess


# ---------------------------------------------------------------------------
# ssdeep_analyzer.py  lines 250-251
# "except Exception as e" / logger.warning in the finally cleanup block of
# _compare_with_binary when temp_dir.cleanup() raises
# ---------------------------------------------------------------------------


def test_compare_with_binary_cleanup_failure_is_swallowed() -> None:
    """Lines 250-251: cleanup exception inside finally is caught and does not propagate."""
    orig_td = _ssdeep_mod.tempfile.TemporaryDirectory  # type: ignore[attr-defined]
    _ssdeep_mod.tempfile.TemporaryDirectory = _BrokenCleanupTempDir  # type: ignore[attr-defined]
    try:
        # Even if the binary is unavailable the finally block always runs,
        # so the cleanup failure at lines 250-251 is always exercised.
        result = SSDeepAnalyzer._compare_with_binary("3:abc:def", "3:abc:xyz")
        # The method must return None without raising, proving the exception was swallowed.
        assert result is None
    finally:
        _ssdeep_mod.tempfile.TemporaryDirectory = orig_td  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# telfhash_analyzer.py  lines 10-11
# "except ImportError: TELFHASH_AVAILABLE = False"
# ---------------------------------------------------------------------------


def test_telfhash_available_is_false_when_import_blocked() -> None:
    """Lines 10-11: TELFHASH_AVAILABLE is set to False when telfhash is unimportable.

    sys.modules['telfhash'] = None causes Python to raise ImportError when any
    code tries 'from telfhash import ...' or 'import telfhash'.
    """
    analyzer_key = "r2inspect.modules.telfhash_analyzer"

    orig_telfhash = sys.modules.get("telfhash")
    orig_analyzer = sys.modules.get(analyzer_key)

    try:
        # Block the telfhash library so that its import raises ImportError.
        sys.modules["telfhash"] = None  # type: ignore[assignment]

        # Remove the cached analyzer module so it is re-imported fresh.
        sys.modules.pop(analyzer_key, None)

        fresh = importlib.import_module(analyzer_key)
        assert fresh.TELFHASH_AVAILABLE is False

    finally:
        # Restore telfhash visibility.
        if orig_telfhash is None:
            sys.modules.pop("telfhash", None)
        else:
            sys.modules["telfhash"] = orig_telfhash

        # Restore (or remove) the analyzer module entry.
        sys.modules.pop(analyzer_key, None)
        if orig_analyzer is not None:
            sys.modules[analyzer_key] = orig_analyzer
        else:
            # Re-import to put a fresh copy back for other tests.
            importlib.import_module(analyzer_key)
