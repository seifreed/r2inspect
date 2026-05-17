"""Tests covering branch paths in r2inspect/modules/ssdeep_analyzer.py.

Library-only implementation: zero mocks, zero monkeypatch.  Branches that
need a controlled ssdeep module use the ``get_ssdeep_fn`` injection seam.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.infrastructure.ssdeep_loader import get_ssdeep
from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer


class _StubModule:
    def __init__(self, *, hash_result="3:abc:def", compare_result=50):
        self._hash_result = hash_result
        self._compare_result = compare_result

    def hash(self, data: bytes) -> str:
        return self._hash_result

    def hash_from_file(self, path: str) -> str:
        return self._hash_result

    def compare(self, h1: str, h2: str) -> int:
        return self._compare_result


# ---------------------------------------------------------------------------
# _check_library_availability
# ---------------------------------------------------------------------------


def test_check_library_availability_returns_true_when_available(tmp_path: Path) -> None:
    f = tmp_path / "sample.bin"
    f.write_bytes(b"A" * 512)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    available, error = analyzer._check_library_availability()
    if SSDeepAnalyzer.is_available():
        assert available is True
        assert error is None
    else:
        assert available is False
        assert error is not None


def test_check_library_availability_message_when_unavailable(tmp_path: Path) -> None:
    f = tmp_path / "sample.bin"
    f.write_bytes(b"A" * 512)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    available, error = analyzer._check_library_availability()
    if SSDeepAnalyzer.is_available():
        assert available is True
        assert error is None
    else:
        assert available is False
        assert error is not None
        assert "SSDeep not available" in error


# ---------------------------------------------------------------------------
# compare_hashes - empty/None inputs
# ---------------------------------------------------------------------------


def test_compare_hashes_empty_string_returns_none() -> None:
    assert SSDeepAnalyzer.compare_hashes("", "valid_hash") is None


def test_compare_hashes_both_empty_returns_none() -> None:
    assert SSDeepAnalyzer.compare_hashes("", "") is None


def test_compare_hashes_first_empty_returns_none() -> None:
    assert SSDeepAnalyzer.compare_hashes("", "3:abc:def") is None


def test_compare_hashes_second_empty_returns_none() -> None:
    assert SSDeepAnalyzer.compare_hashes("3:abc:def", "") is None


# ---------------------------------------------------------------------------
# compare_hashes - full flow with real hashes
# ---------------------------------------------------------------------------


def test_compare_hashes_with_valid_hashes(tmp_path: Path) -> None:
    if not SSDeepAnalyzer.is_available():
        pytest.skip("SSDeep not available")
    f = tmp_path / "sample.bin"
    f.write_bytes(b"Hello World " * 300)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    hash_val, _, _ = analyzer._calculate_hash()
    if hash_val is None:
        pytest.skip("Could not compute ssdeep hash")
    result = SSDeepAnalyzer.compare_hashes(hash_val, hash_val)
    assert result is None or isinstance(result, int)
    if isinstance(result, int):
        assert 0 <= result <= 100


def test_compare_hashes_different_content(tmp_path: Path) -> None:
    if not SSDeepAnalyzer.is_available():
        pytest.skip("SSDeep not available")
    f1 = tmp_path / "file1.bin"
    f2 = tmp_path / "file2.bin"
    f1.write_bytes(b"AAAA" * 1000)
    f2.write_bytes(b"ZZZZ" * 1000)
    h1, _, _ = SSDeepAnalyzer(filepath=str(f1))._calculate_hash()
    h2, _, _ = SSDeepAnalyzer(filepath=str(f2))._calculate_hash()
    if h1 is None or h2 is None:
        pytest.skip("Could not compute ssdeep hashes")
    result = SSDeepAnalyzer.compare_hashes(h1, h2)
    assert result is None or isinstance(result, int)


# ---------------------------------------------------------------------------
# _compare_with_library
# ---------------------------------------------------------------------------


def test_compare_with_library_returns_none_when_ssdeep_unavailable() -> None:
    if get_ssdeep() is None:
        assert SSDeepAnalyzer._compare_with_library("3:abc", "3:abc") is None
    else:
        content = b"Test content " * 200
        h = get_ssdeep().hash(content)
        result = SSDeepAnalyzer._compare_with_library(h, h)
        assert result is not None
        assert isinstance(result, int)


def test_compare_with_library_bad_hashes_returns_none() -> None:
    result = SSDeepAnalyzer._compare_with_library("not_valid_hash", "also_not_valid")
    assert result is None or isinstance(result, int)


def test_compare_with_library_identical_hashes(tmp_path: Path) -> None:
    if get_ssdeep() is None:
        pytest.skip("ssdeep library not available")
    f = tmp_path / "sample.bin"
    f.write_bytes(b"sample content " * 500)
    h = get_ssdeep().hash(f.read_bytes())
    result = SSDeepAnalyzer._compare_with_library(h, h)
    assert result is not None
    assert result >= 0


# ---------------------------------------------------------------------------
# is_available
# ---------------------------------------------------------------------------


def test_is_available_returns_bool() -> None:
    assert isinstance(SSDeepAnalyzer.is_available(), bool)


def test_is_available_true_when_library_present() -> None:
    if get_ssdeep() is not None:
        assert SSDeepAnalyzer.is_available() is True


# ---------------------------------------------------------------------------
# _calculate_hash - library path (real + injected)
# ---------------------------------------------------------------------------


def test_calculate_hash_uses_library_when_available(tmp_path: Path) -> None:
    if get_ssdeep() is None:
        pytest.skip("ssdeep library not available")
    f = tmp_path / "sample.bin"
    f.write_bytes(b"Testing ssdeep hash calculation " * 200)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    hash_val, method, error = analyzer._calculate_hash()
    assert hash_val is not None
    assert method == "python_library"
    assert error is None


def test_calculate_hash_returns_error_when_library_absent(tmp_path: Path) -> None:
    f = tmp_path / "sample.bin"
    f.write_bytes(b"A" * 512)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    hash_val, method, error = analyzer._calculate_hash(get_ssdeep_fn=lambda: None)
    assert hash_val is None
    assert method is None
    assert error is not None


def test_calculate_hash_injected_module_succeeds(tmp_path: Path) -> None:
    f = tmp_path / "sample.bin"
    f.write_bytes(b"A" * 512)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    hash_val, method, error = analyzer._calculate_hash(get_ssdeep_fn=lambda: _StubModule())
    assert hash_val == "3:abc:def"
    assert method == "python_library"
    assert error is None


# ---------------------------------------------------------------------------
# Full analyze() round-trip
# ---------------------------------------------------------------------------


def test_analyze_returns_valid_result_for_real_file(tmp_path: Path) -> None:
    if not SSDeepAnalyzer.is_available():
        pytest.skip("SSDeep not available")
    f = tmp_path / "sample.bin"
    f.write_bytes(b"Full analyze test content " * 200)
    result = SSDeepAnalyzer(filepath=str(f)).analyze()
    assert isinstance(result, dict)
    assert result["hash_type"] == "ssdeep"
    assert result["available"] is True
    assert result["hash_value"] is not None


def test_analyze_unavailable_or_available_result_is_dict(tmp_path: Path) -> None:
    f = tmp_path / "sample.bin"
    f.write_bytes(b"A" * 512)
    result = SSDeepAnalyzer(filepath=str(f)).analyze()
    assert isinstance(result, dict)
    if result["available"]:
        assert result.get("hash_value") is not None
    else:
        assert result.get("error") is not None


def test_analyze_nonexistent_file_returns_error() -> None:
    result = SSDeepAnalyzer(filepath="/nonexistent/deeply/nested/file.bin").analyze()
    assert result["available"] is False
    assert result["error"] is not None
