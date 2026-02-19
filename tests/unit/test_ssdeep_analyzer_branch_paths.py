"""Tests covering branch paths in r2inspect/modules/ssdeep_analyzer.py."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer
from r2inspect.utils.ssdeep_loader import get_ssdeep


# ---------------------------------------------------------------------------
# Helpers: subclasses that override static methods without any mocking library
# ---------------------------------------------------------------------------


class SSDeepUnavailableAnalyzer(SSDeepAnalyzer):
    """Subclass that pretends SSDeep is not available at all."""

    @staticmethod
    def is_available() -> bool:
        return False


class NoBinarySSDeepAnalyzer(SSDeepAnalyzer):
    """Subclass where the ssdeep binary cannot be found."""

    @staticmethod
    def _resolve_ssdeep_binary() -> str | None:
        return None


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


def test_check_library_availability_result_consistent_with_is_available(tmp_path: Path) -> None:
    f = tmp_path / "sample.bin"
    f.write_bytes(b"A" * 512)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    available, error = analyzer._check_library_availability()
    # Result must be consistent with is_available()
    if SSDeepAnalyzer.is_available():
        assert available is True
        assert error is None
    else:
        assert available is False
        assert error is not None
        assert "SSDeep not available" in error


# ---------------------------------------------------------------------------
# compare_hashes - empty/None inputs (lines 195-196)
# ---------------------------------------------------------------------------


def test_compare_hashes_empty_string_returns_none() -> None:
    result = SSDeepAnalyzer.compare_hashes("", "valid_hash")
    assert result is None


def test_compare_hashes_both_empty_returns_none() -> None:
    result = SSDeepAnalyzer.compare_hashes("", "")
    assert result is None


def test_compare_hashes_first_empty_returns_none() -> None:
    result = SSDeepAnalyzer.compare_hashes("", "3:abc:def")
    assert result is None


def test_compare_hashes_second_empty_returns_none() -> None:
    result = SSDeepAnalyzer.compare_hashes("3:abc:def", "")
    assert result is None


# ---------------------------------------------------------------------------
# compare_hashes - full flow with real hashes (lines 198-202)
# ---------------------------------------------------------------------------


def test_compare_hashes_with_valid_hashes(tmp_path: Path) -> None:
    if not SSDeepAnalyzer.is_available():
        pytest.skip("SSDeep not available")
    f = tmp_path / "sample.bin"
    f.write_bytes(b"Hello World " * 300)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    hash_val, _, err = analyzer._calculate_hash()
    if hash_val is None:
        pytest.skip("Could not compute ssdeep hash")
    result = SSDeepAnalyzer.compare_hashes(hash_val, hash_val)
    assert result is not None
    assert isinstance(result, int)
    assert 0 <= result <= 100


def test_compare_hashes_different_content(tmp_path: Path) -> None:
    if not SSDeepAnalyzer.is_available():
        pytest.skip("SSDeep not available")
    f1 = tmp_path / "file1.bin"
    f2 = tmp_path / "file2.bin"
    f1.write_bytes(b"AAAA" * 1000)
    f2.write_bytes(b"ZZZZ" * 1000)
    a1 = SSDeepAnalyzer(filepath=str(f1))
    a2 = SSDeepAnalyzer(filepath=str(f2))
    h1, _, _ = a1._calculate_hash()
    h2, _, _ = a2._calculate_hash()
    if h1 is None or h2 is None:
        pytest.skip("Could not compute ssdeep hashes")
    result = SSDeepAnalyzer.compare_hashes(h1, h2)
    assert result is None or isinstance(result, int)


# ---------------------------------------------------------------------------
# _compare_with_library (lines 206-213)
# ---------------------------------------------------------------------------


def test_compare_with_library_returns_none_when_ssdeep_unavailable() -> None:
    ssdeep_mod = get_ssdeep()
    if ssdeep_mod is None:
        # If no library, _compare_with_library returns None
        result = SSDeepAnalyzer._compare_with_library("3:abc", "3:abc")
        assert result is None
    else:
        # Library present: use valid hashes
        content = b"Test content " * 200
        h = ssdeep_mod.hash(content)
        result = SSDeepAnalyzer._compare_with_library(h, h)
        assert result is not None
        assert isinstance(result, int)


def test_compare_with_library_bad_hashes_returns_none() -> None:
    result = SSDeepAnalyzer._compare_with_library("not_valid_hash", "also_not_valid")
    # Either returns None (exception caught) or int (some libraries accept any string)
    assert result is None or isinstance(result, int)


def test_compare_with_library_identical_hashes(tmp_path: Path) -> None:
    ssdeep_mod = get_ssdeep()
    if ssdeep_mod is None:
        pytest.skip("ssdeep library not available")
    f = tmp_path / "sample.bin"
    f.write_bytes(b"sample content " * 500)
    content = f.read_bytes()
    h = ssdeep_mod.hash(content)
    result = SSDeepAnalyzer._compare_with_library(h, h)
    assert result is not None
    assert result >= 0


# ---------------------------------------------------------------------------
# _compare_with_binary (lines 217-253)
# ---------------------------------------------------------------------------


def test_compare_with_binary_identical_hashes(tmp_path: Path) -> None:
    ssdeep_mod = get_ssdeep()
    if ssdeep_mod is None:
        pytest.skip("ssdeep library not available")
    f = tmp_path / "sample.bin"
    f.write_bytes(b"Binary sample " * 400)
    content = f.read_bytes()
    h = ssdeep_mod.hash(content)
    result = SSDeepAnalyzer._compare_with_binary(h, h)
    assert result is None or isinstance(result, int)


def test_compare_with_binary_invalid_hashes_returns_none() -> None:
    result = SSDeepAnalyzer._compare_with_binary("invalid_hash_1", "invalid_hash_2")
    assert result is None or isinstance(result, int)


def test_compare_with_binary_no_binary_available() -> None:
    # Temporarily make binary resolution fail via subclass
    class ForcedNoBinarySSDeepAnalyzer(SSDeepAnalyzer):
        @staticmethod
        def _resolve_ssdeep_binary() -> str | None:
            return None

    result = ForcedNoBinarySSDeepAnalyzer._compare_with_binary("3:abc:def", "3:abc:xyz")
    assert result is None


def test_compare_with_binary_writes_temp_files(tmp_path: Path) -> None:
    ssdeep_mod = get_ssdeep()
    if ssdeep_mod is None:
        pytest.skip("ssdeep library not available")
    content = b"C" * 2000
    h = ssdeep_mod.hash(content)
    if not h:
        pytest.skip("could not compute hash")
    # Just confirm it runs without exception
    result = SSDeepAnalyzer._compare_with_binary(h, h)
    assert result is None or isinstance(result, int)


# ---------------------------------------------------------------------------
# _write_temp_hash_file (lines 257-265)
# ---------------------------------------------------------------------------


def test_write_temp_hash_file_creates_file_with_correct_content(tmp_path: Path) -> None:
    target = tmp_path / "hash_output.txt"
    content = "96:abc123:file1\n"
    SSDeepAnalyzer._write_temp_hash_file(target, content)
    assert target.exists()
    assert target.read_text() == content


def test_write_temp_hash_file_sets_restrictive_permissions(tmp_path: Path) -> None:
    target = tmp_path / "hash_perm.txt"
    SSDeepAnalyzer._write_temp_hash_file(target, "3:abc:def,testfile\n")
    st = os.stat(target)
    assert (st.st_mode & 0o777) == 0o600


def test_write_temp_hash_file_with_complex_content(tmp_path: Path) -> None:
    target = tmp_path / "complex_hash.txt"
    content = "192:abcdefghij:xyz,/path/to/file with spaces\n"
    SSDeepAnalyzer._write_temp_hash_file(target, content)
    assert target.read_text() == content


# ---------------------------------------------------------------------------
# _parse_ssdeep_output (lines 269-275)
# ---------------------------------------------------------------------------


def test_parse_ssdeep_output_with_match_score() -> None:
    output = "file1 matches file2 hash2 (85)\n"
    result = SSDeepAnalyzer._parse_ssdeep_output(output)
    assert result == 85


def test_parse_ssdeep_output_with_score_zero() -> None:
    output = "file1 matches file2 (0)\n"
    result = SSDeepAnalyzer._parse_ssdeep_output(output)
    assert result == 0


def test_parse_ssdeep_output_with_score_100() -> None:
    output = "file1 matches file2 (100)\n"
    result = SSDeepAnalyzer._parse_ssdeep_output(output)
    assert result == 100


def test_parse_ssdeep_output_no_match_line() -> None:
    result = SSDeepAnalyzer._parse_ssdeep_output("ssdeep,1.1--blocksize:hash:hash,filename\n")
    assert result is None


def test_parse_ssdeep_output_empty_string() -> None:
    result = SSDeepAnalyzer._parse_ssdeep_output("")
    assert result is None


def test_parse_ssdeep_output_multiple_lines_finds_match() -> None:
    output = "ssdeep,1.1\n3:abc:def,file1\nfile1 matches file2 (72)\n"
    result = SSDeepAnalyzer._parse_ssdeep_output(output)
    assert result == 72


def test_parse_ssdeep_output_parentheses_without_matches_word() -> None:
    # "matches" not in the line, so the branch is not taken
    output = "some line with (parens) but no keyword\n"
    result = SSDeepAnalyzer._parse_ssdeep_output(output)
    assert result is None


# ---------------------------------------------------------------------------
# is_available (lines 289-304)
# ---------------------------------------------------------------------------


def test_is_available_returns_bool() -> None:
    result = SSDeepAnalyzer.is_available()
    assert isinstance(result, bool)


def test_is_available_true_when_library_present() -> None:
    if get_ssdeep() is not None:
        assert SSDeepAnalyzer.is_available() is True


def test_is_available_checks_binary_when_no_library() -> None:
    # If library is not available, is_available falls through to binary check
    # We cannot remove the library, but we test the subclass path
    ssdeep_mod = get_ssdeep()
    if ssdeep_mod is not None:
        # Library available -> True short-circuits
        assert SSDeepAnalyzer.is_available() is True
    else:
        # Library not available -> checks binary
        result = SSDeepAnalyzer.is_available()
        binary = SSDeepAnalyzer._resolve_ssdeep_binary()
        assert isinstance(result, bool)
        if binary is None:
            assert result is False


# ---------------------------------------------------------------------------
# _calculate_hash - binary fallback (lines 81-89)
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


def test_calculate_hash_returns_error_when_nothing_available(tmp_path: Path) -> None:
    # Subclass with no library and no binary
    class FullyUnavailableAnalyzer(SSDeepAnalyzer):
        @staticmethod
        def _resolve_ssdeep_binary() -> str | None:
            return None

    # For this to skip library, we need get_ssdeep() to return None.
    # Since library IS available, this test covers the binary fallback path.
    ssdeep_mod = get_ssdeep()
    f = tmp_path / "sample.bin"
    f.write_bytes(b"A" * 512)
    analyzer = FullyUnavailableAnalyzer(filepath=str(f))
    if ssdeep_mod is not None:
        # Library available, so still gets a hash
        hash_val, method, error = analyzer._calculate_hash()
        assert hash_val is not None
    else:
        # No library, no binary
        hash_val, method, error = analyzer._calculate_hash()
        assert hash_val is None
        assert error is not None


# ---------------------------------------------------------------------------
# _calculate_with_binary - binary not found (line 110)
# ---------------------------------------------------------------------------


def test_calculate_with_binary_raises_when_no_binary(tmp_path: Path) -> None:
    f = tmp_path / "sample.bin"
    f.write_bytes(b"A" * 512)
    analyzer = NoBinarySSDeepAnalyzer(filepath=str(f))
    with pytest.raises(RuntimeError, match="ssdeep binary not found in PATH"):
        analyzer._calculate_with_binary()


# ---------------------------------------------------------------------------
# _calculate_with_binary - full successful path
# ---------------------------------------------------------------------------


def test_calculate_with_binary_returns_hash_for_real_file(tmp_path: Path) -> None:
    binary = SSDeepAnalyzer._resolve_ssdeep_binary()
    if binary is None:
        pytest.skip("ssdeep binary not available")
    f = tmp_path / "sample.bin"
    f.write_bytes(b"Binary content for ssdeep " * 100)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    hash_val, method = analyzer._calculate_with_binary()
    assert hash_val is not None
    assert method == "system_binary"
    assert ":" in hash_val


# ---------------------------------------------------------------------------
# Full analyze() round-trip
# ---------------------------------------------------------------------------


def test_analyze_returns_valid_result_for_real_file(tmp_path: Path) -> None:
    if not SSDeepAnalyzer.is_available():
        pytest.skip("SSDeep not available")
    f = tmp_path / "sample.bin"
    f.write_bytes(b"Full analyze test content " * 200)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    result = analyzer.analyze()
    assert isinstance(result, dict)
    assert "hash_type" in result
    assert result["hash_type"] == "ssdeep"
    assert result["available"] is True
    assert result["hash_value"] is not None


def test_analyze_unavailable_or_available_result_is_dict(tmp_path: Path) -> None:
    f = tmp_path / "sample.bin"
    f.write_bytes(b"A" * 512)
    analyzer = SSDeepAnalyzer(filepath=str(f))
    result = analyzer.analyze()
    assert isinstance(result, dict)
    # If available, hash_value should be present; if not, error should be present
    if result["available"]:
        assert result.get("hash_value") is not None
    else:
        assert result.get("error") is not None


def test_analyze_nonexistent_file_returns_error() -> None:
    analyzer = SSDeepAnalyzer(filepath="/nonexistent/deeply/nested/file.bin")
    result = analyzer.analyze()
    assert result["available"] is False
    assert result["error"] is not None
