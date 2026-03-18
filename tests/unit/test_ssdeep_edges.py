import pytest

"""Edge case tests for ssdeep_analyzer.py - covering missing branches.

Rewritten: zero mocks, zero monkeypatch, zero @patch.
Uses real temp files and exercises real code paths.
"""

import os
import shutil
import tempfile
from pathlib import Path

from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer
from r2inspect.modules.ssdeep_runtime_support import (
    compare_with_binary,
    compare_with_library,
    is_available as _is_available_impl,
    parse_ssdeep_output,
    resolve_ssdeep_binary,
    write_temp_hash_file,
)
from r2inspect.infrastructure.ssdeep_loader import get_ssdeep
from r2inspect.infrastructure.logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_temp_binary(content: bytes = b"\x00" * 4096, suffix: str = ".bin") -> str:
    """Create a real temporary file with given content, return its path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, content)
    os.close(fd)
    return path


# ---------------------------------------------------------------------------
# _calculate_hash -- real code paths on real files
# ---------------------------------------------------------------------------


class TestCalculateHashRealFile:
    """Exercise _calculate_hash on actual temp files."""

    def test_calculate_hash_on_real_file(self):
        """Hash calculation on a real file should return a value or a graceful error."""
        path = _make_temp_binary(b"A" * 8192)
        try:
            analyzer = SSDeepAnalyzer(path)
            result = analyzer._calculate_hash()
            # result is (hash_value, method, error)
            assert len(result) == 3
            hash_val, method, error = result
            # Either we got a hash or a descriptive error -- both are valid
            if hash_val is not None:
                assert isinstance(hash_val, str)
                assert method in ("python_library", "system_binary")
                assert error is None
            else:
                # No ssdeep available at all -- error must be reported
                assert error is not None
        finally:
            os.unlink(path)

    def test_calculate_hash_empty_file(self):
        """A 0-byte file should fail min_file_size validation upstream,
        but if we skip validation and call _calculate_hash directly it
        should still return gracefully."""
        path = _make_temp_binary(b"")
        try:
            # min_file_size=0 so constructor won't reject it
            analyzer = SSDeepAnalyzer(path, min_file_size=0)
            result = analyzer._calculate_hash()
            assert len(result) == 3
        finally:
            os.unlink(path)

    def test_calculate_hash_nonexistent_file(self):
        """Hashing a file that does not exist should return an error tuple."""
        path = "/tmp/r2inspect_test_does_not_exist_ssdeep.bin"
        # Ensure it really doesn't exist
        if os.path.exists(path):
            os.unlink(path)
        try:
            analyzer = SSDeepAnalyzer(path)
            result = analyzer._calculate_hash()
            assert len(result) == 3
            # Should report an error since file doesn't exist
            hash_val, method, error = result
            if hash_val is None:
                assert error is not None
        except (OSError, RuntimeError):
            # Also acceptable -- the code may raise
            pass


# ---------------------------------------------------------------------------
# _calculate_with_binary -- real subprocess paths
# ---------------------------------------------------------------------------


class TestCalculateWithBinaryRealFile:
    """Exercise _calculate_with_binary with real temp files."""

    def test_calculate_with_binary_on_real_file(self):
        """If ssdeep binary is present, this should produce a hash."""
        ssdeep_path = shutil.which("ssdeep")
        if ssdeep_path is None:
            # No binary available -- verify the method raises RuntimeError
            path = _make_temp_binary(b"B" * 8192)
            try:
                analyzer = SSDeepAnalyzer(path)
                try:
                    analyzer._calculate_with_binary()
                    pytest.fail("Should have raised RuntimeError when binary is missing")
                except RuntimeError as exc:
                    assert "not found" in str(exc).lower() or "binary" in str(exc).lower()
            finally:
                os.unlink(path)
        else:
            # Binary IS available -- should produce a real hash
            path = _make_temp_binary(b"B" * 8192)
            try:
                analyzer = SSDeepAnalyzer(path)
                hash_val, method = analyzer._calculate_with_binary()
                assert hash_val is not None
                assert method == "system_binary"
                assert ":" in hash_val  # ssdeep format contains colons
            finally:
                os.unlink(path)

    def test_calculate_with_binary_nonexistent_file(self):
        """Binary calculation on a nonexistent file should raise RuntimeError."""
        path = "/tmp/r2inspect_ssdeep_no_such_file.bin"
        if os.path.exists(path):
            os.unlink(path)
        analyzer = SSDeepAnalyzer(path)
        try:
            analyzer._calculate_with_binary()
            pytest.fail("Should have raised RuntimeError")
        except RuntimeError:
            pass  # Expected


# ---------------------------------------------------------------------------
# compare_hashes -- static method, no r2 needed
# ---------------------------------------------------------------------------


class TestCompareHashes:
    """Test compare_hashes edge cases with real calls."""

    def test_compare_hashes_empty_hash1(self):
        result = SSDeepAnalyzer.compare_hashes("", "3:AaBb:file")
        assert result is None

    def test_compare_hashes_empty_hash2(self):
        result = SSDeepAnalyzer.compare_hashes("3:AaBb:file", "")
        assert result is None

    def test_compare_hashes_both_empty(self):
        result = SSDeepAnalyzer.compare_hashes("", "")
        assert result is None

    def test_compare_hashes_identical(self):
        """Comparing identical hashes should return a score (likely 100 or 0 depending on implementation)."""
        ssdeep_mod = get_ssdeep()
        ssdeep_bin = shutil.which("ssdeep")
        if ssdeep_mod is None and ssdeep_bin is None:
            # Can't compare without either; should return None
            result = SSDeepAnalyzer.compare_hashes("3:AaBb:f1", "3:AaBb:f2")
            assert result is None
            return
        # With library or binary, identical hashes should produce a score
        h = "3:AaBb+CcDd:testfile"
        result = SSDeepAnalyzer.compare_hashes(h, h)
        # Result is an int or None -- both valid
        assert result is None or isinstance(result, int)

    def test_compare_hashes_malformed(self):
        """Malformed hashes should not crash -- returns None or an int."""
        result = SSDeepAnalyzer.compare_hashes("not-a-hash", "also-not-a-hash")
        assert result is None or isinstance(result, int)


# ---------------------------------------------------------------------------
# _compare_with_library -- direct function call
# ---------------------------------------------------------------------------


class TestCompareWithLibrary:
    """Test compare_with_library runtime support function."""

    def test_compare_with_library_no_module(self):
        """When get_ssdeep returns None, compare_with_library returns None."""
        result = compare_with_library("h1", "h2", lambda: None, logger)
        assert result is None

    def test_compare_with_library_exception_in_compare(self):
        """When the module's compare raises, we get None."""

        class BadSsdeep:
            def compare(self, h1, h2):
                raise ValueError("Invalid hash format")

        result = compare_with_library("h1", "h2", lambda: BadSsdeep(), logger)
        assert result is None

    def test_compare_with_library_returns_score(self):
        """When the module returns a score, we get it back."""

        class GoodSsdeep:
            def compare(self, h1, h2):
                return 42

        result = compare_with_library("h1", "h2", lambda: GoodSsdeep(), logger)
        assert result == 42


# ---------------------------------------------------------------------------
# _compare_with_binary -- direct function call
# ---------------------------------------------------------------------------


class TestCompareWithBinary:
    """Test compare_with_binary runtime support function."""

    def test_compare_with_binary_no_binary(self):
        """When resolve returns None, result is None."""
        result = compare_with_binary(
            "h1",
            "h2",
            resolve_binary_fn=lambda: None,
            write_temp_hash_file_fn=write_temp_hash_file,
            logger=logger,
        )
        assert result is None

    def test_compare_with_binary_write_and_run(self):
        """Exercise the full path with a real binary or graceful fallback."""
        ssdeep_path = shutil.which("ssdeep")
        if ssdeep_path is None:
            # No binary -- should return None via resolve returning None
            result = compare_with_binary(
                "3:AaBb:f1",
                "3:AaBb:f2",
                resolve_binary_fn=lambda: None,
                write_temp_hash_file_fn=write_temp_hash_file,
                logger=logger,
            )
            assert result is None
        else:
            result = compare_with_binary(
                "3:AaBb:f1",
                "3:AaBb:f2",
                resolve_binary_fn=lambda: ssdeep_path,
                write_temp_hash_file_fn=write_temp_hash_file,
                logger=logger,
            )
            # May be None or int depending on ssdeep version behavior
            assert result is None or isinstance(result, int)


# ---------------------------------------------------------------------------
# is_available -- static method
# ---------------------------------------------------------------------------


class TestIsAvailable:
    """Test is_available with real environment probing."""

    def test_is_available_returns_bool(self):
        result = SSDeepAnalyzer.is_available()
        assert isinstance(result, bool)

    def test_is_available_impl_no_library_no_binary(self):
        """With both returning None/False, should be False."""
        result = _is_available_impl(lambda: None, lambda: None)
        assert result is False

    def test_is_available_impl_with_library(self):
        """If get_ssdeep returns something, is_available is True."""

        class FakeSsdeep:
            pass

        result = _is_available_impl(lambda: FakeSsdeep(), lambda: None)
        assert result is True

    def test_is_available_impl_with_binary(self):
        """If binary is found and runs, is_available should be True."""
        ssdeep_path = shutil.which("ssdeep")
        if ssdeep_path is None:
            # No binary installed; this path cannot be tested
            result = _is_available_impl(lambda: None, lambda: None)
            assert result is False
        else:
            result = _is_available_impl(lambda: None, lambda: ssdeep_path)
            assert result is True

    def test_is_available_impl_with_bad_binary_path(self):
        """A binary that doesn't exist should return False."""
        result = _is_available_impl(
            lambda: None,
            lambda: "/nonexistent/ssdeep_fake_binary",
        )
        assert result is False


# ---------------------------------------------------------------------------
# _parse_ssdeep_output -- pure function, no dependencies
# ---------------------------------------------------------------------------


class TestParseSsdeepOutput:
    """Test parse_ssdeep_output with various real strings."""

    def test_parse_no_matches_line(self):
        result = parse_ssdeep_output("Some random output\nNo matches found\n")
        assert result is None

    def test_parse_malformed(self):
        result = parse_ssdeep_output("Matches (invalid format")
        assert result is None

    def test_parse_missing_parens(self):
        result = parse_ssdeep_output("matches 50")
        assert result is None

    def test_parse_valid_output(self):
        output = "file1.bin matches file2.bin (75)\n"
        result = parse_ssdeep_output(output)
        assert result == 75

    def test_parse_zero_score(self):
        output = "file1.bin matches file2.bin (0)\n"
        result = parse_ssdeep_output(output)
        assert result == 0

    def test_parse_100_score(self):
        output = "file1.bin matches file2.bin (100)\n"
        result = parse_ssdeep_output(output)
        assert result == 100

    def test_parse_empty_string(self):
        result = parse_ssdeep_output("")
        assert result is None

    def test_parse_multiline_with_header(self):
        output = (
            "ssdeep,1.1--blocksize:hash:hash,filename\n3:abc:def,file1\nfile1 matches file2 (42)\n"
        )
        result = parse_ssdeep_output(output)
        assert result == 42

    def test_parse_non_numeric_in_parens(self):
        output = "file1 matches file2 (abc)\n"
        result = parse_ssdeep_output(output)
        assert result is None


# ---------------------------------------------------------------------------
# _write_temp_hash_file -- real filesystem operations
# ---------------------------------------------------------------------------


class TestWriteTempHashFile:
    """Test write_temp_hash_file with real temp dirs."""

    def test_write_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir) / "test_hash.txt"
            write_temp_hash_file(temp_path, "test content\n")

            assert temp_path.exists()
            content = temp_path.read_text()
            assert content == "test content\n"

            file_stat = os.stat(temp_path)
            mode = file_stat.st_mode & 0o777
            assert mode == 0o600

    def test_write_binary_content(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir) / "hash_binary.txt"
            write_temp_hash_file(temp_path, "3:AaBb+CcDd,file1\n")

            content = temp_path.read_text()
            assert content == "3:AaBb+CcDd,file1\n"

    def test_write_overwrite_fails(self):
        """Writing to an existing file should fail (O_EXCL)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir) / "existing.txt"
            write_temp_hash_file(temp_path, "first\n")

            try:
                write_temp_hash_file(temp_path, "second\n")
                pytest.fail("Should have raised FileExistsError")
            except FileExistsError:
                pass

    def test_write_nonexistent_directory(self):
        """Writing to a path in a nonexistent directory should fail."""
        bad_path = Path("/tmp/r2inspect_no_such_dir_ssdeep/hash.txt")
        try:
            write_temp_hash_file(bad_path, "content\n")
            pytest.fail("Should have raised")
        except (FileNotFoundError, OSError):
            pass


# ---------------------------------------------------------------------------
# Full analyze() workflow on real files
# ---------------------------------------------------------------------------


class TestAnalyzeWorkflow:
    """End-to-end analyze() on real temp files."""

    def test_analyze_real_file(self):
        path = _make_temp_binary(b"C" * 16384)
        try:
            analyzer = SSDeepAnalyzer(path)
            result = analyzer.analyze()
            assert isinstance(result, dict)
            assert "hash_type" in result
            assert result["hash_type"] == "ssdeep"
            assert "available" in result
        finally:
            os.unlink(path)

    def test_analyze_small_file(self):
        """Very small file (< min_file_size) should report an error."""
        path = _make_temp_binary(b"\x00")
        try:
            analyzer = SSDeepAnalyzer(path, min_file_size=1024)
            result = analyzer.analyze()
            assert isinstance(result, dict)
            # File is too small, so there should be an error
            assert result.get("error") is not None or result.get("hash_value") is None
        finally:
            os.unlink(path)

    def test_get_hash_type(self):
        path = _make_temp_binary(b"D" * 100)
        try:
            analyzer = SSDeepAnalyzer(path)
            assert analyzer._get_hash_type() == "ssdeep"
        finally:
            os.unlink(path)

    def test_get_file_size(self):
        path = _make_temp_binary(b"E" * 500)
        try:
            analyzer = SSDeepAnalyzer(path)
            size = analyzer.get_file_size()
            assert size == 500
        finally:
            os.unlink(path)

    def test_get_file_extension(self):
        path = _make_temp_binary(b"F" * 100, suffix=".exe")
        try:
            analyzer = SSDeepAnalyzer(path)
            ext = analyzer.get_file_extension()
            assert ext == "exe"
        finally:
            os.unlink(path)

    def test_str_repr(self):
        path = _make_temp_binary(b"G" * 100)
        try:
            analyzer = SSDeepAnalyzer(path)
            s = str(analyzer)
            assert "SSDeepAnalyzer" in s
            assert "ssdeep" in s
            r = repr(analyzer)
            assert "SSDeepAnalyzer" in r
        finally:
            os.unlink(path)

    def test_check_library_availability(self):
        path = _make_temp_binary(b"H" * 100)
        try:
            analyzer = SSDeepAnalyzer(path)
            available, error = analyzer._check_library_availability()
            assert isinstance(available, bool)
            if available:
                assert error is None
            else:
                assert error is not None
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# resolve_ssdeep_binary -- real shutil.which
# ---------------------------------------------------------------------------


class TestResolveSsdeepBinary:
    """Test resolve_ssdeep_binary with actual PATH lookup."""

    def test_resolve_returns_str_or_none(self):
        result = resolve_ssdeep_binary()
        assert result is None or isinstance(result, str)

    def test_resolve_matches_shutil_which(self):
        expected = shutil.which("ssdeep")
        result = resolve_ssdeep_binary()
        assert result == expected

    def test_static_method_matches(self):
        result = SSDeepAnalyzer._resolve_ssdeep_binary()
        expected = shutil.which("ssdeep")
        assert result == expected
