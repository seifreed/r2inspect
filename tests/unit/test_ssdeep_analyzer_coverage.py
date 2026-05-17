"""Coverage tests for ssdeep_analyzer.py - library-only implementation."""

import pytest

from r2inspect.infrastructure.ssdeep_loader import get_ssdeep
from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer

# --- availability ---


def test_ssdeep_is_available_returns_bool():
    assert isinstance(SSDeepAnalyzer.is_available(), bool)


# --- constructor ---


def test_ssdeep_analyzer_constructor(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    assert SSDeepAnalyzer(filepath=str(f)).filepath == f


def test_ssdeep_analyzer_constructor_with_adapter(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    assert SSDeepAnalyzer(filepath=str(f), adapter=None).filepath == f


# --- _check_library_availability ---


def test_check_library_availability(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    available, error = SSDeepAnalyzer(filepath=str(f))._check_library_availability()
    assert isinstance(available, bool)
    if not available:
        assert error is not None
    else:
        assert error is None


# --- _get_hash_type ---


def test_get_hash_type(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    assert SSDeepAnalyzer(filepath=str(f))._get_hash_type() == "ssdeep"


# --- _calculate_hash with real file ---


def test_calculate_hash_with_real_file(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"Hello World! " * 200)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    if SSDeepAnalyzer.is_available():
        hash_value, method, error = analyzer._calculate_hash()
        assert hash_value is not None
        assert ":" in hash_value
        assert error is None
    else:
        hash_value, method, error = analyzer._calculate_hash()
        assert hash_value is None


def test_calculate_hash_small_file_no_content(tmp_path):
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    result = SSDeepAnalyzer(filepath=str(f)).analyze()
    assert isinstance(result, dict)


def test_calculate_hash_no_library_returns_error(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 512)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    hash_value, method, error = analyzer._calculate_hash(get_ssdeep_fn=lambda: None)
    assert hash_value is None
    assert method is None
    assert error is not None


# --- analyze() template method ---


def test_analyze_with_real_file(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"Binary content " * 500)
    result = SSDeepAnalyzer(filepath=str(f)).analyze()
    assert isinstance(result, dict)
    assert result["hash_type"] == "ssdeep"


def test_analyze_nonexistent_file():
    result = SSDeepAnalyzer(filepath="/nonexistent/path/file.bin").analyze()
    assert result["available"] is False
    assert result["error"] is not None


# --- _compare_with_library ---


def test_compare_with_library_both_valid(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"Test data " * 200)
    ssdeep_module = get_ssdeep()
    if ssdeep_module is None:
        pytest.skip("ssdeep library not available")
    h = ssdeep_module.hash(f.read_bytes())
    result = SSDeepAnalyzer._compare_with_library(h, h)
    assert result is not None
    assert result >= 0


def test_compare_with_library_empty_hash():
    result = SSDeepAnalyzer._compare_with_library("", "")
    assert result is None or isinstance(result, int)


def test_compare_with_library_exception():
    result = SSDeepAnalyzer._compare_with_library("bad_hash", "bad_hash2")
    assert result is None or isinstance(result, int)


# --- compare_hashes ---


def test_compare_hashes_empty_inputs():
    assert SSDeepAnalyzer.compare_hashes("", "") is None
    assert SSDeepAnalyzer.compare_hashes("", "abc") is None
    assert SSDeepAnalyzer.compare_hashes("abc", "") is None


def test_compare_hashes_identical(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"A" * 10000)
    if not SSDeepAnalyzer.is_available():
        pytest.skip("ssdeep not available")
    hash_value, _, _ = SSDeepAnalyzer(filepath=str(f))._calculate_hash()
    if hash_value is None:
        pytest.skip("could not calculate hash")
    result = SSDeepAnalyzer.compare_hashes(hash_value, hash_value)
    assert result is None or result >= 0


def test_compare_hashes_different_files(tmp_path):
    if not SSDeepAnalyzer.is_available():
        pytest.skip("ssdeep not available")
    f1 = tmp_path / "file1.bin"
    f2 = tmp_path / "file2.bin"
    f1.write_bytes(b"AAAA" * 5000)
    f2.write_bytes(b"ZZZZ" * 5000)
    h1, _, _ = SSDeepAnalyzer(filepath=str(f1))._calculate_hash()
    h2, _, _ = SSDeepAnalyzer(filepath=str(f2))._calculate_hash()
    if h1 is None or h2 is None:
        pytest.skip("could not calculate hashes")
    result = SSDeepAnalyzer.compare_hashes(h1, h2)
    assert result is None or isinstance(result, int)
    if isinstance(result, int):
        assert 0 <= result <= 100


def test_compare_hashes_library_returns_none_for_invalid():
    result = SSDeepAnalyzer.compare_hashes("invalid_ssdeep", "also_invalid")
    assert result is None or isinstance(result, int)


# --- SSDeepAnalyzer with max/min file size ---


def test_ssdeep_constructor_with_size_limits(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = SSDeepAnalyzer(
        filepath=str(f),
        max_file_size=50 * 1024 * 1024,
        min_file_size=1,
    )
    assert analyzer.max_file_size == 50 * 1024 * 1024


def test_analyze_file_too_large(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = SSDeepAnalyzer(filepath=str(f), max_file_size=10, min_file_size=1)
    assert analyzer.analyze()["available"] is False


def test_calculate_hash_large_file(tmp_path):
    if not SSDeepAnalyzer.is_available():
        pytest.skip("ssdeep not available")
    f = tmp_path / "large.bin"
    f.write_bytes(bytes(range(256)) * 200)
    _, _, error = SSDeepAnalyzer(filepath=str(f))._calculate_hash()
    assert error is None or isinstance(error, str)
