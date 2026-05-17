"""Comprehensive tests for ssdeep_analyzer.py - library-only implementation.

NO mocks, NO monkeypatch, NO patch decorators.  Uses hand-rolled stub doubles, the
``get_ssdeep_fn`` dependency-injection seam, and real temp files to exercise
every surviving branch in the production code.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from r2inspect.infrastructure.ssdeep_loader import get_ssdeep
from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer
from r2inspect.modules.ssdeep_runtime_support import (
    compare_with_library as _compare_with_library_impl,
    is_available as _is_available_impl,
)

# ---------------------------------------------------------------------------
# Helpers: subclasses / stubs that override behaviour without mocking
# ---------------------------------------------------------------------------


class _AlwaysAvailableSSDeep(SSDeepAnalyzer):
    """Reports itself as always available."""

    @staticmethod
    def is_available() -> bool:
        return True


class _NeverAvailableSSDeep(SSDeepAnalyzer):
    """Reports itself as never available."""

    @staticmethod
    def is_available() -> bool:
        return False


class _StubSSDeepModule:
    """Mimics the ssdeep Python library API."""

    def __init__(
        self,
        *,
        hash_result: str | Exception = "3:abc:def",
        hash_from_file_result: str | Exception = "3:abc:def",
        compare_result: int | Exception = 50,
    ):
        self._hash_result = hash_result
        self._hash_from_file_result = hash_from_file_result
        self._compare_result = compare_result

    def hash(self, data: bytes) -> str:
        if isinstance(self._hash_result, Exception):
            raise self._hash_result
        return self._hash_result

    def hash_from_file(self, filepath: str) -> str:
        if isinstance(self._hash_from_file_result, Exception):
            raise self._hash_from_file_result
        return self._hash_from_file_result

    def compare(self, h1: str, h2: str) -> int:
        if isinstance(self._compare_result, Exception):
            raise self._compare_result
        return self._compare_result


class _StubLogger:
    """Captures log calls without any mocking library."""

    def __init__(self) -> None:
        self.warnings: list[str] = []
        self.debugs: list[str] = []

    def warning(self, msg: str, *args: Any) -> None:
        self.warnings.append(msg % args if args else msg)

    def debug(self, msg: str, *args: Any) -> None:
        self.debugs.append(msg % args if args else msg)

    def error(self, msg: str, *args: Any) -> None:
        pass

    def info(self, msg: str, *args: Any) -> None:
        pass


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


def test_init(tmp_path: Path) -> None:
    f = tmp_path / "sample.bin"
    f.write_bytes(b"A" * 256)
    analyzer = SSDeepAnalyzer(str(f))
    assert analyzer.filepath == f


def test_init_stores_filepath_as_path(tmp_path: Path) -> None:
    f = tmp_path / "other.bin"
    f.write_bytes(b"B" * 128)
    analyzer = SSDeepAnalyzer(str(f))
    assert isinstance(analyzer.filepath, Path)


# ---------------------------------------------------------------------------
# _get_hash_type
# ---------------------------------------------------------------------------


def test_get_hash_type(tmp_path: Path) -> None:
    f = tmp_path / "x.bin"
    f.write_bytes(b"\x00" * 64)
    assert SSDeepAnalyzer(str(f))._get_hash_type() == "ssdeep"


# ---------------------------------------------------------------------------
# _check_library_availability
# ---------------------------------------------------------------------------


def test_check_library_availability_consistent_with_is_available(tmp_path: Path) -> None:
    f = tmp_path / "a.bin"
    f.write_bytes(b"A" * 64)
    analyzer = SSDeepAnalyzer(str(f))
    avail, err = analyzer._check_library_availability()
    if SSDeepAnalyzer.is_available():
        assert avail is True
        assert err is None
    else:
        assert avail is False
        assert err is not None
        assert "not available" in err.lower()


# ---------------------------------------------------------------------------
# is_available (static)
# ---------------------------------------------------------------------------


def test_is_available_returns_bool() -> None:
    result = SSDeepAnalyzer.is_available()
    assert isinstance(result, bool)


def test_is_available_always_available() -> None:
    assert _AlwaysAvailableSSDeep.is_available() is True


def test_is_available_never_available() -> None:
    assert _NeverAvailableSSDeep.is_available() is False


# ---------------------------------------------------------------------------
# is_available runtime support – exercised with controlled callables
# ---------------------------------------------------------------------------


def test_is_available_impl_with_library() -> None:
    assert _is_available_impl(lambda: _StubSSDeepModule()) is True


def test_is_available_impl_no_library() -> None:
    assert _is_available_impl(lambda: None) is False


# ---------------------------------------------------------------------------
# _calculate_hash – library path (real + injected)
# ---------------------------------------------------------------------------


def test_calculate_hash_library_success(tmp_path: Path) -> None:
    """When the ssdeep Python library is installed, _calculate_hash should work."""
    if get_ssdeep() is None:
        pytest.skip("ssdeep Python library not installed")
    f = tmp_path / "payload.bin"
    f.write_bytes(os.urandom(4096))
    analyzer = SSDeepAnalyzer(str(f))
    h, method, error = analyzer._calculate_hash()
    assert h is not None
    assert method == "python_library"
    assert error is None


def test_calculate_hash_injected_library_success(tmp_path: Path) -> None:
    f = tmp_path / "payload.bin"
    f.write_bytes(b"A" * 256)
    analyzer = SSDeepAnalyzer(str(f))
    stub = _StubSSDeepModule(hash_result="3:stub:hash")
    h, method, error = analyzer._calculate_hash(get_ssdeep_fn=lambda: stub)
    assert h == "3:stub:hash"
    assert method == "python_library"
    assert error is None


def test_calculate_hash_no_library_returns_error(tmp_path: Path) -> None:
    f = tmp_path / "payload.bin"
    f.write_bytes(b"A" * 256)
    analyzer = SSDeepAnalyzer(str(f))
    h, method, error = analyzer._calculate_hash(get_ssdeep_fn=lambda: None)
    assert h is None
    assert method is None
    assert error is not None
    assert "not available" in error.lower()


def test_calculate_hash_oserror_falls_back_to_hash_from_file() -> None:
    """read_bytes raises OSError (missing file) -> hash_from_file succeeds."""
    analyzer = SSDeepAnalyzer("/nonexistent/r2inspect_ssdeep_complete100.bin")
    stub = _StubSSDeepModule(hash_from_file_result="3:fromfile:hash")
    h, method, error = analyzer._calculate_hash(get_ssdeep_fn=lambda: stub)
    assert h == "3:fromfile:hash"
    assert method == "python_library"
    assert error is None


def test_calculate_hash_oserror_then_hash_from_file_fails() -> None:
    analyzer = SSDeepAnalyzer("/nonexistent/r2inspect_ssdeep_complete100b.bin")
    stub = _StubSSDeepModule(hash_from_file_result=RuntimeError("hash_from_file boom"))
    h, method, error = analyzer._calculate_hash(get_ssdeep_fn=lambda: stub)
    assert h is None
    assert method is None
    assert error is not None
    assert "library error" in error.lower()


def test_calculate_hash_library_hash_raises_non_oserror(tmp_path: Path) -> None:
    f = tmp_path / "payload.bin"
    f.write_bytes(b"A" * 256)
    analyzer = SSDeepAnalyzer(str(f))
    stub = _StubSSDeepModule(hash_result=RuntimeError("hash boom"))
    h, method, error = analyzer._calculate_hash(get_ssdeep_fn=lambda: stub)
    assert h is None
    assert method is None
    assert error is not None
    assert "library error" in error.lower()


# ---------------------------------------------------------------------------
# compare_hashes
# ---------------------------------------------------------------------------


def test_compare_hashes_empty_hash1() -> None:
    assert SSDeepAnalyzer.compare_hashes("", "hash2") is None


def test_compare_hashes_empty_hash2() -> None:
    assert SSDeepAnalyzer.compare_hashes("hash1", "") is None


def test_compare_hashes_both_empty() -> None:
    assert SSDeepAnalyzer.compare_hashes("", "") is None


def test_compare_hashes_with_library() -> None:
    if get_ssdeep() is None:
        pytest.skip("ssdeep Python library not installed")
    h = "3:abc:def"
    result = SSDeepAnalyzer.compare_hashes(h, h)
    assert result is not None
    assert isinstance(result, int)


# ---------------------------------------------------------------------------
# compare_with_library (runtime support)
# ---------------------------------------------------------------------------


def test_compare_with_library_impl_success() -> None:
    stub = _StubSSDeepModule(compare_result=85)
    logger = _StubLogger()
    result = _compare_with_library_impl("h1", "h2", lambda: stub, logger)
    assert result == 85


def test_compare_with_library_impl_no_module() -> None:
    logger = _StubLogger()
    result = _compare_with_library_impl("h1", "h2", lambda: None, logger)
    assert result is None


def test_compare_with_library_impl_exception() -> None:
    stub = _StubSSDeepModule(compare_result=RuntimeError("compare fail"))
    logger = _StubLogger()
    result = _compare_with_library_impl("h1", "h2", lambda: stub, logger)
    assert result is None
    assert any("failed" in w.lower() for w in logger.warnings)


# ---------------------------------------------------------------------------
# Full analyze() template method integration
# ---------------------------------------------------------------------------


def test_analyze_returns_dict(tmp_path: Path) -> None:
    f = tmp_path / "analyze_target.bin"
    f.write_bytes(os.urandom(4096))
    analyzer = SSDeepAnalyzer(str(f))
    result = analyzer.analyze()
    assert isinstance(result, dict)
    assert "hash_type" in result
    assert result["hash_type"] == "ssdeep"


def test_analyze_unavailable(tmp_path: Path) -> None:
    f = tmp_path / "unavail.bin"
    f.write_bytes(b"X" * 256)
    analyzer = _NeverAvailableSSDeep(str(f))
    result = analyzer.analyze()
    assert isinstance(result, dict)
    if not SSDeepAnalyzer.is_available():
        assert result.get("available") is False or result.get("error") is not None


def test_analyze_nonexistent_file() -> None:
    analyzer = SSDeepAnalyzer("/nonexistent/path/does_not_exist.bin")
    result = analyzer.analyze()
    assert isinstance(result, dict)
    assert result.get("error") is not None or result.get("hash_value") is None


def test_analyze_empty_file(tmp_path: Path) -> None:
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    analyzer = SSDeepAnalyzer(str(f))
    result = analyzer.analyze()
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# get_file_size / get_file_extension (inherited from HashingStrategy)
# ---------------------------------------------------------------------------


def test_get_file_size(tmp_path: Path) -> None:
    f = tmp_path / "sized.bin"
    f.write_bytes(b"A" * 1024)
    analyzer = SSDeepAnalyzer(str(f))
    assert analyzer.get_file_size() == 1024


def test_get_file_size_missing() -> None:
    analyzer = SSDeepAnalyzer("/nonexistent/file.bin")
    assert analyzer.get_file_size() is None


def test_get_file_extension(tmp_path: Path) -> None:
    f = tmp_path / "sample.exe"
    f.write_bytes(b"\x00" * 64)
    analyzer = SSDeepAnalyzer(str(f))
    assert analyzer.get_file_extension() == "exe"


def test_get_file_extension_no_ext(tmp_path: Path) -> None:
    f = tmp_path / "noext"
    f.write_bytes(b"\x00" * 64)
    analyzer = SSDeepAnalyzer(str(f))
    assert analyzer.get_file_extension() == ""


# ---------------------------------------------------------------------------
# __str__ / __repr__
# ---------------------------------------------------------------------------


def test_str_representation(tmp_path: Path) -> None:
    f = tmp_path / "repr.bin"
    f.write_bytes(b"\x00" * 64)
    analyzer = SSDeepAnalyzer(str(f))
    s = str(analyzer)
    assert "SSDeepAnalyzer" in s
    assert "ssdeep" in s


def test_repr_representation(tmp_path: Path) -> None:
    f = tmp_path / "repr.bin"
    f.write_bytes(b"\x00" * 64)
    analyzer = SSDeepAnalyzer(str(f))
    r = repr(analyzer)
    assert "SSDeepAnalyzer" in r
    assert "filepath" in r
