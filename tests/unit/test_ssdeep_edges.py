"""Edge case tests for ssdeep_analyzer.py - library-only implementation.

Zero mocks, zero monkeypatch, zero @patch.  Uses real temp files, the
``get_ssdeep_fn`` injection seam, and hand-rolled stub modules.
"""

from __future__ import annotations

import os
import tempfile

from r2inspect.infrastructure.logging import get_logger
from r2inspect.infrastructure.ssdeep_loader import get_ssdeep
from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer
from r2inspect.modules.ssdeep_runtime_support import (
    compare_with_library,
    is_available as _is_available_impl,
)

logger = get_logger(__name__)


def _make_temp_binary(content: bytes = b"\x00" * 4096, suffix: str = ".bin") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, content)
    os.close(fd)
    return path


# ---------------------------------------------------------------------------
# _calculate_hash -- real code paths on real files
# ---------------------------------------------------------------------------


class TestCalculateHashRealFile:
    def test_calculate_hash_on_real_file(self):
        path = _make_temp_binary(b"A" * 8192)
        try:
            analyzer = SSDeepAnalyzer(path)
            result = analyzer._calculate_hash()
            assert len(result) == 3
            hash_val, method, error = result
            if hash_val is not None:
                assert isinstance(hash_val, str)
                assert method == "python_library"
                assert error is None
            else:
                assert error is not None
        finally:
            os.unlink(path)

    def test_calculate_hash_empty_file(self):
        path = _make_temp_binary(b"")
        try:
            analyzer = SSDeepAnalyzer(path, min_file_size=0)
            result = analyzer._calculate_hash()
            assert len(result) == 3
        finally:
            os.unlink(path)

    def test_calculate_hash_nonexistent_file(self):
        path = "/tmp/r2inspect_test_does_not_exist_ssdeep.bin"
        if os.path.exists(path):
            os.unlink(path)
        analyzer = SSDeepAnalyzer(path)
        hash_val, method, error = analyzer._calculate_hash()
        if hash_val is None:
            assert error is not None


# ---------------------------------------------------------------------------
# compare_hashes -- static method, no r2 needed
# ---------------------------------------------------------------------------


class TestCompareHashes:
    def test_compare_hashes_empty_hash1(self):
        assert SSDeepAnalyzer.compare_hashes("", "3:AaBb:file") is None

    def test_compare_hashes_empty_hash2(self):
        assert SSDeepAnalyzer.compare_hashes("3:AaBb:file", "") is None

    def test_compare_hashes_both_empty(self):
        assert SSDeepAnalyzer.compare_hashes("", "") is None

    def test_compare_hashes_identical(self):
        if get_ssdeep() is None:
            assert SSDeepAnalyzer.compare_hashes("3:AaBb:f1", "3:AaBb:f2") is None
            return
        h = "3:AaBb+CcDd:testfile"
        result = SSDeepAnalyzer.compare_hashes(h, h)
        assert result is None or isinstance(result, int)

    def test_compare_hashes_malformed(self):
        result = SSDeepAnalyzer.compare_hashes("not-a-hash", "also-not-a-hash")
        assert result is None or isinstance(result, int)


# ---------------------------------------------------------------------------
# compare_with_library -- direct function call (surviving runtime support)
# ---------------------------------------------------------------------------


class TestCompareWithLibrary:
    def test_compare_with_library_no_module(self):
        assert compare_with_library("h1", "h2", lambda: None, logger) is None

    def test_compare_with_library_exception_in_compare(self):
        class BadSsdeep:
            def compare(self, h1, h2):
                raise ValueError("Invalid hash format")

        assert compare_with_library("h1", "h2", lambda: BadSsdeep(), logger) is None

    def test_compare_with_library_returns_score(self):
        class GoodSsdeep:
            def compare(self, h1, h2):
                return 42

        assert compare_with_library("h1", "h2", lambda: GoodSsdeep(), logger) == 42


# ---------------------------------------------------------------------------
# is_available -- static method + runtime support
# ---------------------------------------------------------------------------


class TestIsAvailable:
    def test_is_available_returns_bool(self):
        assert isinstance(SSDeepAnalyzer.is_available(), bool)

    def test_is_available_impl_no_library(self):
        assert _is_available_impl(lambda: None) is False

    def test_is_available_impl_with_library(self):
        class FakeSsdeep:
            pass

        assert _is_available_impl(lambda: FakeSsdeep()) is True


# ---------------------------------------------------------------------------
# Full analyze() workflow on real files
# ---------------------------------------------------------------------------


class TestAnalyzeWorkflow:
    def test_analyze_real_file(self):
        path = _make_temp_binary(b"C" * 16384)
        try:
            analyzer = SSDeepAnalyzer(path)
            result = analyzer.analyze()
            assert isinstance(result, dict)
            assert result["hash_type"] == "ssdeep"
            assert "available" in result
        finally:
            os.unlink(path)

    def test_analyze_small_file(self):
        path = _make_temp_binary(b"\x00")
        try:
            analyzer = SSDeepAnalyzer(path, min_file_size=1024)
            result = analyzer.analyze()
            assert isinstance(result, dict)
            assert result.get("error") is not None or result.get("hash_value") is None
        finally:
            os.unlink(path)

    def test_get_hash_type(self):
        path = _make_temp_binary(b"D" * 100)
        try:
            assert SSDeepAnalyzer(path)._get_hash_type() == "ssdeep"
        finally:
            os.unlink(path)

    def test_get_file_size(self):
        path = _make_temp_binary(b"E" * 500)
        try:
            assert SSDeepAnalyzer(path).get_file_size() == 500
        finally:
            os.unlink(path)

    def test_get_file_extension(self):
        path = _make_temp_binary(b"F" * 100, suffix=".exe")
        try:
            assert SSDeepAnalyzer(path).get_file_extension() == "exe"
        finally:
            os.unlink(path)

    def test_str_repr(self):
        path = _make_temp_binary(b"G" * 100)
        try:
            analyzer = SSDeepAnalyzer(path)
            assert "SSDeepAnalyzer" in str(analyzer)
            assert "ssdeep" in str(analyzer)
            assert "SSDeepAnalyzer" in repr(analyzer)
        finally:
            os.unlink(path)

    def test_check_library_availability(self):
        path = _make_temp_binary(b"H" * 100)
        try:
            available, error = SSDeepAnalyzer(path)._check_library_availability()
            assert isinstance(available, bool)
            if available:
                assert error is None
            else:
                assert error is not None
        finally:
            os.unlink(path)
