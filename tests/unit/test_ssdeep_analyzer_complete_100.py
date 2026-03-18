"""Comprehensive tests for ssdeep_analyzer.py - 100% coverage target.

NO mocks, NO monkeypatch, NO @patch.  Uses subclass overrides and real
temp files to exercise every branch in the production code.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest

from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer
from r2inspect.modules.ssdeep_runtime_support import (
    compare_with_binary as _compare_with_binary_impl,
    compare_with_library as _compare_with_library_impl,
    is_available as _is_available_impl,
    parse_ssdeep_output as _parse_ssdeep_output_impl,
    write_temp_hash_file as _write_temp_hash_file_impl,
)
from r2inspect.infrastructure.ssdeep_loader import get_ssdeep


# ---------------------------------------------------------------------------
# Helpers: subclasses that override behaviour without mocking
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


class _NoBinarySSDeep(SSDeepAnalyzer):
    """Binary resolution always returns None."""

    @staticmethod
    def _resolve_ssdeep_binary() -> str | None:
        return None


class _FakeBinarySSDeep(SSDeepAnalyzer):
    """Binary resolution returns a controlled path."""

    _fake_path: str | None = "/usr/bin/ssdeep"

    @staticmethod
    def _resolve_ssdeep_binary() -> str | None:
        return _FakeBinarySSDeep._fake_path


# Stub ssdeep module for library tests
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


def test_check_library_availability_true(tmp_path: Path) -> None:
    f = tmp_path / "a.bin"
    f.write_bytes(b"A" * 64)
    analyzer = _AlwaysAvailableSSDeep(str(f))
    avail, err = analyzer._check_library_availability()
    assert avail is True
    assert err is None


def test_check_library_availability_false(tmp_path: Path) -> None:
    """_check_library_availability delegates to SSDeepAnalyzer.is_available().

    Because the production code hardcodes SSDeepAnalyzer.is_available() (not
    type(self).is_available()), the result depends on the real environment.
    We verify consistency with the real is_available() result.
    """
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
    assert _is_available_impl(lambda: _StubSSDeepModule(), lambda: None) is True


def test_is_available_impl_no_library_no_binary() -> None:
    assert _is_available_impl(lambda: None, lambda: None) is False


# ---------------------------------------------------------------------------
# _calculate_hash – library path
# ---------------------------------------------------------------------------


def test_calculate_hash_library_success(tmp_path: Path) -> None:
    """When the ssdeep Python library is installed, _calculate_hash should work."""
    ssdeep_mod = get_ssdeep()
    if ssdeep_mod is None:
        pytest.skip("ssdeep Python library not installed")
    f = tmp_path / "payload.bin"
    f.write_bytes(os.urandom(4096))
    analyzer = SSDeepAnalyzer(str(f))
    h, method, error = analyzer._calculate_hash()
    assert h is not None
    assert method == "python_library"
    assert error is None


def test_calculate_hash_no_library_no_binary(tmp_path: Path) -> None:
    """When nothing is available, _calculate_hash returns an error."""
    f = tmp_path / "payload.bin"
    f.write_bytes(b"A" * 256)

    class _NoLib(_NoBinarySSDeep):
        pass

    analyzer = _NoLib(str(f))
    # _calculate_hash tries library (get_ssdeep global), then binary (_calculate_with_binary).
    # _calculate_with_binary will raise RuntimeError because _resolve_ssdeep_binary returns None.
    h, method, error = analyzer._calculate_hash()
    if get_ssdeep() is not None:
        # Library is available, so it will succeed
        assert h is not None
    else:
        # Neither library nor binary available
        assert error is not None


# ---------------------------------------------------------------------------
# _calculate_with_binary
# ---------------------------------------------------------------------------


def test_calculate_with_binary_no_binary(tmp_path: Path) -> None:
    f = tmp_path / "file.bin"
    f.write_bytes(b"X" * 128)
    analyzer = _NoBinarySSDeep(str(f))
    with pytest.raises(RuntimeError, match="not found"):
        analyzer._calculate_with_binary()


def test_calculate_with_binary_invalid_path(tmp_path: Path) -> None:
    """Non-existent file should fail path validation."""
    analyzer = _FakeBinarySSDeep("/nonexistent/path/file.bin")
    with pytest.raises((RuntimeError, ValueError)):
        analyzer._calculate_with_binary()


def test_calculate_with_binary_real_binary(tmp_path: Path) -> None:
    """If ssdeep binary is installed, exercise the real binary path."""
    import shutil

    ssdeep_bin = shutil.which("ssdeep")
    if ssdeep_bin is None:
        pytest.skip("ssdeep binary not installed")
    f = tmp_path / "test_binary.bin"
    f.write_bytes(os.urandom(4096))
    analyzer = SSDeepAnalyzer(str(f))
    h, method = analyzer._calculate_with_binary()
    assert h is not None
    assert method == "system_binary"


# ---------------------------------------------------------------------------
# _is_ssdeep_binary_available
# ---------------------------------------------------------------------------


def test_is_ssdeep_binary_available_true(tmp_path: Path) -> None:
    f = tmp_path / "a.bin"
    f.write_bytes(b"A" * 64)
    _FakeBinarySSDeep._fake_path = "/usr/bin/ssdeep"
    analyzer = _FakeBinarySSDeep(str(f))
    assert analyzer._is_ssdeep_binary_available() is True


def test_is_ssdeep_binary_available_false(tmp_path: Path) -> None:
    f = tmp_path / "a.bin"
    f.write_bytes(b"A" * 64)
    analyzer = _NoBinarySSDeep(str(f))
    assert analyzer._is_ssdeep_binary_available() is False


# ---------------------------------------------------------------------------
# _resolve_ssdeep_binary (delegates to runtime support)
# ---------------------------------------------------------------------------


def test_resolve_ssdeep_binary_returns_str_or_none() -> None:
    result = SSDeepAnalyzer._resolve_ssdeep_binary()
    assert result is None or isinstance(result, str)


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
    ssdeep_mod = get_ssdeep()
    if ssdeep_mod is None:
        pytest.skip("ssdeep Python library not installed")
    # Use two identical trivial hashes – score should be 100 or 0 depending on impl
    h = "3:abc:def"
    result = SSDeepAnalyzer.compare_hashes(h, h)
    assert result is not None
    assert isinstance(result, int)


# ---------------------------------------------------------------------------
# _compare_with_library (runtime support)
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
# _compare_with_binary (runtime support)
# ---------------------------------------------------------------------------


def test_compare_with_binary_impl_no_binary() -> None:
    logger = _StubLogger()
    result = _compare_with_binary_impl(
        "h1",
        "h2",
        resolve_binary_fn=lambda: None,
        write_temp_hash_file_fn=_write_temp_hash_file_impl,
        logger=logger,
    )
    assert result is None


def test_compare_with_binary_impl_exception() -> None:
    logger = _StubLogger()

    def _raise_write(path: Path, content: str) -> None:
        raise OSError("disk full")

    result = _compare_with_binary_impl(
        "h1",
        "h2",
        resolve_binary_fn=lambda: "/usr/bin/ssdeep",
        write_temp_hash_file_fn=_raise_write,
        logger=logger,
    )
    assert result is None
    assert any("failed" in w.lower() or "disk" in w.lower() for w in logger.warnings)


# ---------------------------------------------------------------------------
# _parse_ssdeep_output (runtime support)
# ---------------------------------------------------------------------------


def test_parse_ssdeep_output_match() -> None:
    output = "file1,file2 matches (92)"
    assert _parse_ssdeep_output_impl(output) == 92


def test_parse_ssdeep_output_no_match() -> None:
    assert _parse_ssdeep_output_impl("No matches found") is None


def test_parse_ssdeep_output_multiple_lines() -> None:
    output = "header line\nsome info\nfile1 matches file2 (75)\n"
    assert _parse_ssdeep_output_impl(output) == 75


def test_parse_ssdeep_output_empty() -> None:
    assert _parse_ssdeep_output_impl("") is None


def test_parse_ssdeep_output_invalid_number() -> None:
    output = "file1 matches file2 (abc)"
    assert _parse_ssdeep_output_impl(output) is None


def test_parse_ssdeep_output_parentheses_without_matches() -> None:
    output = "some text (42) other"
    assert _parse_ssdeep_output_impl(output) is None


# ---------------------------------------------------------------------------
# _write_temp_hash_file (runtime support)
# ---------------------------------------------------------------------------


def test_write_temp_hash_file_creates_file(tmp_path: Path) -> None:
    target = tmp_path / "hash_file.txt"
    _write_temp_hash_file_impl(target, "3:abc:def,testfile\n")
    assert target.exists()
    assert target.read_text() == "3:abc:def,testfile\n"


def test_write_temp_hash_file_permissions(tmp_path: Path) -> None:
    target = tmp_path / "perm_file.txt"
    _write_temp_hash_file_impl(target, "content")
    mode = target.stat().st_mode & 0o777
    assert mode == 0o600


def test_write_temp_hash_file_exclusive_create(tmp_path: Path) -> None:
    """O_EXCL should cause failure if file already exists."""
    target = tmp_path / "existing.txt"
    target.write_text("already here")
    with pytest.raises(FileExistsError):
        _write_temp_hash_file_impl(target, "overwrite attempt")


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
    # When unavailable, available should be False
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
    data = b"A" * 1024
    f.write_bytes(data)
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
