"""Tests targeting remaining uncovered lines in ssdeep_analyzer.py.

Uses module-attribute patching (no unittest.mock) to hit:
  47, 71-72, 134, 149, 202, 208, 230, 242, 244-245, 289-304
"""

import subprocess as _subprocess

import r2inspect.modules.ssdeep_analyzer as _ssd_mod
from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer

FIXTURE_PE = "samples/fixtures/hello_pe.exe"


class _BasicAdapter:
    def get_file_info(self):
        return {}

    def cmdj(self, cmd):
        return None

    def cmd(self, cmd):
        return ""


# ---------------------------------------------------------------------------
# Fake ssdeep module used in multiple tests
# ---------------------------------------------------------------------------


class _FakeSsdeepOSError:
    """Simulates ssdeep where hash() raises OSError but hash_from_file succeeds."""

    def hash(self, data):
        raise OSError("simulated read error")

    def hash_from_file(self, path):
        return "3:abc:def"

    def compare(self, h1, h2):
        return 50


# ---------------------------------------------------------------------------
# Line 47 – _check_library_availability returns (False, msg)
# ---------------------------------------------------------------------------


def test_check_library_availability_unavailable():
    """Line 47: returns (False, message) when is_available() is False."""
    orig_is_avail = SSDeepAnalyzer.is_available
    SSDeepAnalyzer.is_available = staticmethod(lambda: False)
    try:
        analyzer = SSDeepAnalyzer(filepath=FIXTURE_PE)
        ok, msg = analyzer._check_library_availability()
        assert ok is False
        assert msg is not None and len(msg) > 0
    finally:
        SSDeepAnalyzer.is_available = orig_is_avail


# ---------------------------------------------------------------------------
# Lines 71-72 – _calculate_hash OSError fallback to hash_from_file
# ---------------------------------------------------------------------------


def test_calculate_hash_oserror_fallback_to_hash_from_file():
    """Lines 71-72: when hash(data) raises OSError, falls back to hash_from_file."""
    orig_get_ssdeep = _ssd_mod.get_ssdeep
    _ssd_mod.get_ssdeep = lambda: _FakeSsdeepOSError()
    try:
        analyzer = SSDeepAnalyzer(filepath=FIXTURE_PE)
        result_hash, method, err = analyzer._calculate_hash()
        assert result_hash == "3:abc:def"
        assert method == "python_library"
        assert err is None
    finally:
        _ssd_mod.get_ssdeep = orig_get_ssdeep


# ---------------------------------------------------------------------------
# Line 134 – _calculate_with_binary raises when returncode != 0
# ---------------------------------------------------------------------------


class _BadRunResult:
    returncode = 1
    stderr = "simulated ssdeep error"
    stdout = ""


def test_calculate_with_binary_nonzero_returncode():
    """Line 134: raises RuntimeError when subprocess returncode != 0."""
    orig_run = _ssd_mod.subprocess.run
    _ssd_mod.subprocess.run = lambda *a, **kw: _BadRunResult()
    orig_resolve = SSDeepAnalyzer._resolve_ssdeep_binary
    SSDeepAnalyzer._resolve_ssdeep_binary = staticmethod(lambda: "/opt/homebrew/bin/ssdeep")
    try:
        analyzer = SSDeepAnalyzer(filepath=FIXTURE_PE)
        try:
            analyzer._calculate_with_binary()
            raise AssertionError("Expected RuntimeError")
        except RuntimeError as exc:
            assert "ssdeep command failed" in str(exc)
    finally:
        _ssd_mod.subprocess.run = orig_run
        SSDeepAnalyzer._resolve_ssdeep_binary = orig_resolve


# ---------------------------------------------------------------------------
# Line 149 – _calculate_with_binary raises RuntimeError on TimeoutExpired
# ---------------------------------------------------------------------------


def test_calculate_with_binary_timeout():
    """Line 149: raises RuntimeError when subprocess raises TimeoutExpired."""

    def _timeout_run(*a, **kw):
        raise _subprocess.TimeoutExpired(cmd="ssdeep", timeout=30)

    orig_run = _ssd_mod.subprocess.run
    _ssd_mod.subprocess.run = _timeout_run
    orig_resolve = SSDeepAnalyzer._resolve_ssdeep_binary
    SSDeepAnalyzer._resolve_ssdeep_binary = staticmethod(lambda: "/opt/homebrew/bin/ssdeep")
    try:
        analyzer = SSDeepAnalyzer(filepath=FIXTURE_PE)
        try:
            analyzer._calculate_with_binary()
            raise AssertionError("Expected RuntimeError")
        except RuntimeError as exc:
            assert "timed out" in str(exc)
    finally:
        _ssd_mod.subprocess.run = orig_run
        SSDeepAnalyzer._resolve_ssdeep_binary = orig_resolve


# ---------------------------------------------------------------------------
# Line 202 – compare_hashes falls through to _compare_with_binary
# Line 208 – _compare_with_library returns None when get_ssdeep() is None
# ---------------------------------------------------------------------------


def test_compare_hashes_library_unavailable_falls_through():
    """Lines 202, 208: when get_ssdeep() is None, _compare_with_library returns None
    and compare_hashes calls _compare_with_binary (which may also return None)."""
    orig_get_ssdeep = _ssd_mod.get_ssdeep
    _ssd_mod.get_ssdeep = lambda: None
    try:
        result = SSDeepAnalyzer.compare_hashes("3:abc:def", "3:abc:ghi")
        # Both methods unavailable/failed → None
        assert result is None
    finally:
        _ssd_mod.get_ssdeep = orig_get_ssdeep


def test_compare_with_library_returns_none_when_no_module():
    """Line 208: _compare_with_library returns None when get_ssdeep() is None."""
    orig_get_ssdeep = _ssd_mod.get_ssdeep
    _ssd_mod.get_ssdeep = lambda: None
    try:
        result = SSDeepAnalyzer._compare_with_library("3:abc:def", "3:abc:ghi")
        assert result is None
    finally:
        _ssd_mod.get_ssdeep = orig_get_ssdeep


# ---------------------------------------------------------------------------
# Line 230 – _compare_with_binary returns None when no binary found
# ---------------------------------------------------------------------------


def test_compare_with_binary_no_binary_returns_none():
    """Line 230: returns None when _resolve_ssdeep_binary() returns None."""
    orig_resolve = SSDeepAnalyzer._resolve_ssdeep_binary
    SSDeepAnalyzer._resolve_ssdeep_binary = staticmethod(lambda: None)
    try:
        result = SSDeepAnalyzer._compare_with_binary("3:abc:def", "3:abc:ghi")
        assert result is None
    finally:
        SSDeepAnalyzer._resolve_ssdeep_binary = orig_resolve


# ---------------------------------------------------------------------------
# Line 242 – _compare_with_binary returns parsed output on returncode==0
# ---------------------------------------------------------------------------


class _GoodRunResult:
    returncode = 0
    stdout = "file2 matches file1 (75)\n"
    stderr = ""


def test_compare_with_binary_success_parses_output():
    """Line 242: when returncode==0, returns _parse_ssdeep_output result."""
    orig_run = _ssd_mod.subprocess.run
    _ssd_mod.subprocess.run = lambda *a, **kw: _GoodRunResult()
    orig_resolve = SSDeepAnalyzer._resolve_ssdeep_binary
    SSDeepAnalyzer._resolve_ssdeep_binary = staticmethod(lambda: "/opt/homebrew/bin/ssdeep")
    try:
        result = SSDeepAnalyzer._compare_with_binary("3:abc:def", "3:abc:ghi")
        assert result == 75
    finally:
        _ssd_mod.subprocess.run = orig_run
        SSDeepAnalyzer._resolve_ssdeep_binary = orig_resolve


# ---------------------------------------------------------------------------
# Lines 244-245 – _compare_with_binary catches unexpected exceptions
# ---------------------------------------------------------------------------


def test_compare_with_binary_unexpected_exception():
    """Lines 244-245: unexpected exception is caught and None is returned."""

    def _boom(*a, **kw):
        raise ValueError("unexpected internal error")

    orig_run = _ssd_mod.subprocess.run
    _ssd_mod.subprocess.run = _boom
    orig_resolve = SSDeepAnalyzer._resolve_ssdeep_binary
    SSDeepAnalyzer._resolve_ssdeep_binary = staticmethod(lambda: "/opt/homebrew/bin/ssdeep")
    try:
        result = SSDeepAnalyzer._compare_with_binary("3:abc:def", "3:abc:ghi")
        assert result is None
    finally:
        _ssd_mod.subprocess.run = orig_run
        SSDeepAnalyzer._resolve_ssdeep_binary = orig_resolve


# ---------------------------------------------------------------------------
# Lines 289-292, 302 – is_available() binary path succeeds
# ---------------------------------------------------------------------------


class _VersionOkResult:
    returncode = 0
    stdout = "ssdeep 2.14\n"
    stderr = ""


def test_is_available_binary_path_returns_true():
    """Lines 289-292, 302: when library unavailable but binary runs OK → True."""
    orig_get_ssdeep = _ssd_mod.get_ssdeep
    _ssd_mod.get_ssdeep = lambda: None
    orig_run = _ssd_mod.subprocess.run
    _ssd_mod.subprocess.run = lambda *a, **kw: _VersionOkResult()
    orig_resolve = SSDeepAnalyzer._resolve_ssdeep_binary
    SSDeepAnalyzer._resolve_ssdeep_binary = staticmethod(lambda: "/opt/homebrew/bin/ssdeep")
    try:
        result = SSDeepAnalyzer.is_available()
        assert result is True
    finally:
        _ssd_mod.get_ssdeep = orig_get_ssdeep
        _ssd_mod.subprocess.run = orig_run
        SSDeepAnalyzer._resolve_ssdeep_binary = orig_resolve


def test_is_available_binary_path_no_binary():
    """Lines 289-292: _resolve_ssdeep_binary returns None → False."""
    orig_get_ssdeep = _ssd_mod.get_ssdeep
    _ssd_mod.get_ssdeep = lambda: None
    orig_resolve = SSDeepAnalyzer._resolve_ssdeep_binary
    SSDeepAnalyzer._resolve_ssdeep_binary = staticmethod(lambda: None)
    try:
        result = SSDeepAnalyzer.is_available()
        assert result is False
    finally:
        _ssd_mod.get_ssdeep = orig_get_ssdeep
        SSDeepAnalyzer._resolve_ssdeep_binary = orig_resolve


# ---------------------------------------------------------------------------
# Lines 303-304 – is_available() catches SubprocessError / FileNotFoundError
# ---------------------------------------------------------------------------


def test_is_available_binary_subprocess_error():
    """Line 303-304: SubprocessError → returns False."""
    orig_get_ssdeep = _ssd_mod.get_ssdeep
    _ssd_mod.get_ssdeep = lambda: None
    orig_resolve = SSDeepAnalyzer._resolve_ssdeep_binary
    SSDeepAnalyzer._resolve_ssdeep_binary = staticmethod(lambda: "/opt/homebrew/bin/ssdeep")
    orig_run = _ssd_mod.subprocess.run

    def _raise_subprocess(*a, **kw):
        raise _subprocess.SubprocessError("subprocess failed")

    _ssd_mod.subprocess.run = _raise_subprocess
    try:
        result = SSDeepAnalyzer.is_available()
        assert result is False
    finally:
        _ssd_mod.get_ssdeep = orig_get_ssdeep
        SSDeepAnalyzer._resolve_ssdeep_binary = orig_resolve
        _ssd_mod.subprocess.run = orig_run


def test_is_available_binary_file_not_found():
    """Line 303-304: FileNotFoundError → returns False."""
    orig_get_ssdeep = _ssd_mod.get_ssdeep
    _ssd_mod.get_ssdeep = lambda: None
    orig_resolve = SSDeepAnalyzer._resolve_ssdeep_binary
    SSDeepAnalyzer._resolve_ssdeep_binary = staticmethod(lambda: "/opt/homebrew/bin/ssdeep")
    orig_run = _ssd_mod.subprocess.run

    def _raise_fnf(*a, **kw):
        raise FileNotFoundError("binary not found")

    _ssd_mod.subprocess.run = _raise_fnf
    try:
        result = SSDeepAnalyzer.is_available()
        assert result is False
    finally:
        _ssd_mod.get_ssdeep = orig_get_ssdeep
        SSDeepAnalyzer._resolve_ssdeep_binary = orig_resolve
        _ssd_mod.subprocess.run = orig_run
