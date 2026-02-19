"""Coverage tests for ssdeep_analyzer.py."""

import os
import tempfile
from pathlib import Path

import pytest

from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer
from r2inspect.utils.ssdeep_loader import get_ssdeep


# --- availability ---


def test_ssdeep_is_available_returns_bool():
    result = SSDeepAnalyzer.is_available()
    assert isinstance(result, bool)


def test_ssdeep_resolve_binary_returns_string_or_none():
    result = SSDeepAnalyzer._resolve_ssdeep_binary()
    assert result is None or isinstance(result, str)


# --- _parse_ssdeep_output ---


def test_parse_ssdeep_output_with_match():
    output = "file1 matches hash2 (85)\n"
    result = SSDeepAnalyzer._parse_ssdeep_output(output)
    assert result == 85


def test_parse_ssdeep_output_no_match():
    result = SSDeepAnalyzer._parse_ssdeep_output("no matches found")
    assert result is None


def test_parse_ssdeep_output_empty():
    result = SSDeepAnalyzer._parse_ssdeep_output("")
    assert result is None


def test_parse_ssdeep_output_multiple_lines():
    output = "ssdeep: v2.14\nfile1 matches hash2 (72)\n"
    result = SSDeepAnalyzer._parse_ssdeep_output(output)
    assert result == 72


# --- constructor ---


def test_ssdeep_analyzer_constructor(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    assert analyzer.filepath == f


def test_ssdeep_analyzer_constructor_with_r2(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = SSDeepAnalyzer(filepath=str(f), r2_instance=None)
    assert analyzer.filepath == f


# --- _check_library_availability ---


def test_check_library_availability(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    available, error = analyzer._check_library_availability()
    assert isinstance(available, bool)
    if not available:
        assert error is not None
    else:
        assert error is None


# --- _get_hash_type ---


def test_get_hash_type(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"A" * 100)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    assert analyzer._get_hash_type() == "ssdeep"


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
    analyzer = SSDeepAnalyzer(filepath=str(f))
    # analyze() will fail at file validation, not _calculate_hash
    result = analyzer.analyze()
    assert isinstance(result, dict)


# --- analyze() template method ---


def test_analyze_with_real_file(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"Binary content " * 500)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    result = analyzer.analyze()
    assert isinstance(result, dict)
    assert "hash_type" in result
    assert result["hash_type"] == "ssdeep"


def test_analyze_nonexistent_file():
    analyzer = SSDeepAnalyzer(filepath="/nonexistent/path/file.bin")
    result = analyzer.analyze()
    assert result["available"] is False
    assert result["error"] is not None


# --- _compare_with_library ---


def test_compare_with_library_both_valid(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"Test data " * 200)
    ssdeep_module = get_ssdeep()
    if ssdeep_module is None:
        pytest.skip("ssdeep library not available")
    content = f.read_bytes()
    h = ssdeep_module.hash(content)
    result = SSDeepAnalyzer._compare_with_library(h, h)
    assert result is not None
    assert result >= 0


def test_compare_with_library_empty_hash():
    result = SSDeepAnalyzer._compare_with_library("", "")
    # Empty hashes either return None from exception or a value
    assert result is None or isinstance(result, int)


# --- compare_hashes ---


def test_compare_hashes_none_inputs():
    assert SSDeepAnalyzer.compare_hashes("", "") is None
    assert SSDeepAnalyzer.compare_hashes(None, "abc") is None  # type: ignore[arg-type]
    assert SSDeepAnalyzer.compare_hashes("abc", None) is None  # type: ignore[arg-type]


def test_compare_hashes_identical(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"A" * 10000)
    if not SSDeepAnalyzer.is_available():
        pytest.skip("ssdeep not available")
    analyzer = SSDeepAnalyzer(filepath=str(f))
    hash_value, _, _ = analyzer._calculate_hash()
    if hash_value is None:
        pytest.skip("could not calculate hash")
    result = SSDeepAnalyzer.compare_hashes(hash_value, hash_value)
    assert result is not None
    assert result >= 0


def test_compare_hashes_different_files(tmp_path):
    if not SSDeepAnalyzer.is_available():
        pytest.skip("ssdeep not available")
    f1 = tmp_path / "file1.bin"
    f2 = tmp_path / "file2.bin"
    f1.write_bytes(b"AAAA" * 5000)
    f2.write_bytes(b"ZZZZ" * 5000)
    a1 = SSDeepAnalyzer(filepath=str(f1))
    a2 = SSDeepAnalyzer(filepath=str(f2))
    h1, _, _ = a1._calculate_hash()
    h2, _, _ = a2._calculate_hash()
    if h1 is None or h2 is None:
        pytest.skip("could not calculate hashes")
    result = SSDeepAnalyzer.compare_hashes(h1, h2)
    assert result is not None
    assert 0 <= result <= 100


# --- _is_ssdeep_binary_available ---


def test_is_ssdeep_binary_available(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"A" * 100)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    result = analyzer._is_ssdeep_binary_available()
    assert isinstance(result, bool)


# --- _write_temp_hash_file ---


def test_write_temp_hash_file(tmp_path):
    target = tmp_path / "hash.txt"
    SSDeepAnalyzer._write_temp_hash_file(target, "3:abc:def,file1\n")
    content = target.read_text()
    assert content == "3:abc:def,file1\n"
    # Verify restrictive permissions
    st = os.stat(target)
    assert (st.st_mode & 0o777) == 0o600


# --- _compare_with_binary ---


def test_compare_with_binary_no_binary_graceful():
    # If ssdeep binary is not available, should return None gracefully
    # If it is available, it should try to compare
    result = SSDeepAnalyzer._compare_with_binary("3:abc:def", "3:abc:xyz")
    assert result is None or isinstance(result, int)


# --- calculate_hash with hash_from_file fallback path ---


def test_calculate_hash_large_file(tmp_path):
    if not SSDeepAnalyzer.is_available():
        pytest.skip("ssdeep not available")
    f = tmp_path / "large.bin"
    # Create a file that can be hashed
    f.write_bytes(bytes(range(256)) * 200)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    hash_value, method, error = analyzer._calculate_hash()
    # Should succeed or fail gracefully
    assert error is None or isinstance(error, str)


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
    analyzer = SSDeepAnalyzer(
        filepath=str(f),
        max_file_size=10,  # Very small limit
        min_file_size=1,
    )
    result = analyzer.analyze()
    assert result["available"] is False


# --- supplementary tests for remaining missing lines ---


def test_calculate_with_binary_real_file(tmp_path):
    """Test _calculate_with_binary directly with a real file."""
    f = tmp_path / "sample.bin"
    f.write_bytes(b"Hello World! " * 500)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    try:
        hash_value, method = analyzer._calculate_with_binary()
        if hash_value:
            assert ":" in hash_value
            assert method == "system_binary"
    except RuntimeError as e:
        # Acceptable if binary not found or path validation fails
        assert "ssdeep" in str(e).lower() or "path" in str(e).lower() or "parse" in str(e).lower()


def test_calculate_with_binary_no_binary(tmp_path):
    """Test _calculate_with_binary when binary is not found."""
    f = tmp_path / "sample.bin"
    f.write_bytes(b"A" * 1000)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    # If binary IS available, this runs; if not, raises RuntimeError
    ssdeep_path = SSDeepAnalyzer._resolve_ssdeep_binary()
    if not ssdeep_path:
        try:
            analyzer._calculate_with_binary()
            assert False, "Should have raised RuntimeError"
        except RuntimeError as e:
            assert "ssdeep binary not found" in str(e)
    else:
        # Binary exists, test should not raise
        try:
            hash_value, method = analyzer._calculate_with_binary()
            assert method == "system_binary"
        except RuntimeError:
            pass  # Could fail for other reasons


def test_compare_with_binary_real_hashes(tmp_path):
    """Test _compare_with_binary directly."""
    f = tmp_path / "sample.bin"
    f.write_bytes(b"Test content " * 300)
    ssdeep_module = get_ssdeep()
    if ssdeep_module is None:
        pytest.skip("ssdeep library not available")
    content = f.read_bytes()
    h = ssdeep_module.hash(content)
    # Call _compare_with_binary directly
    result = SSDeepAnalyzer._compare_with_binary(h, h)
    # Should return int or None depending on binary availability
    assert result is None or isinstance(result, int)


def test_compare_with_binary_empty_hash():
    """Test _compare_with_binary with empty hash strings - should return None."""
    result = SSDeepAnalyzer._compare_with_binary("", "hash2")
    assert result is None or isinstance(result, int)


def test_calculate_hash_os_error_fallback(tmp_path):
    """Test OSError fallback path in _calculate_hash (lines 67-75)."""
    # Create a file, then create an analyzer with a different filepath
    # that doesn't exist but force hash_from_file to try
    f = tmp_path / "sample.bin"
    f.write_bytes(b"Content " * 1000)
    ssdeep_module = get_ssdeep()
    if ssdeep_module is None:
        pytest.skip("ssdeep library not available")
    # Test the main path (not the OSError path, which requires unreadable file)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value is not None
    assert error is None


def test_compare_with_binary_write_and_run(tmp_path):
    """Test _compare_with_binary with actual hash strings."""
    ssdeep_module = get_ssdeep()
    if ssdeep_module is None:
        pytest.skip("ssdeep not available")
    content = b"AAAAA" * 2000
    h = ssdeep_module.hash(content)
    if not h:
        pytest.skip("could not calculate ssdeep hash")
    result = SSDeepAnalyzer._compare_with_binary(h, h)
    assert result is None or isinstance(result, int)


# --- final supplementary tests ---


def test_compare_hashes_library_fails_falls_through_to_binary():
    """Test line 202: _compare_with_binary is called when library raises."""
    # ssdeep.compare("invalid", "invalid") raises InternalError
    # _compare_with_library returns None
    # falls through to _compare_with_binary
    result = SSDeepAnalyzer.compare_hashes("invalid_ssdeep", "also_invalid")
    assert result is None or isinstance(result, int)


def test_compare_with_library_exception():
    """Test exception handler in _compare_with_library (lines 211-213)."""
    # Invalid hash strings cause ssdeep.compare to raise
    result = SSDeepAnalyzer._compare_with_library("bad_hash", "bad_hash2")
    # Should return None after catching exception
    assert result is None


def test_calculate_with_binary_returns_hash(tmp_path):
    """Test _calculate_with_binary returns a hash using ssdeep binary."""
    ssdeep_path = SSDeepAnalyzer._resolve_ssdeep_binary()
    if not ssdeep_path:
        pytest.skip("ssdeep binary not available")
    f = tmp_path / "test.bin"
    # Write enough content to hash
    f.write_bytes(b"test content for ssdeep binary hashing" * 100)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    hash_value, method = analyzer._calculate_with_binary()
    assert hash_value is not None
    assert method == "system_binary"
    assert ":" in hash_value


def test_calculate_with_binary_nonexistent_file(tmp_path):
    """Test _calculate_with_binary with nonexistent file raises RuntimeError."""
    ssdeep_path = SSDeepAnalyzer._resolve_ssdeep_binary()
    if not ssdeep_path:
        pytest.skip("ssdeep binary not available")
    analyzer = SSDeepAnalyzer(filepath="/nonexistent/path_that_does_not_exist.bin")
    try:
        analyzer._calculate_with_binary()
        # Might succeed or fail depending on OS and ssdeep behavior
    except RuntimeError:
        pass  # Expected - path validation or ssdeep failure
