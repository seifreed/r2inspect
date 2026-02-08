import os
import sys
from pathlib import Path

import pytest

import r2inspect.abstractions as abstractions
import r2inspect.core as core
import r2inspect.schemas as schemas
from r2inspect.__main__ import main as package_main
from r2inspect.abstractions.base_analyzer import BaseAnalyzer
from r2inspect.abstractions.hashing_strategy import HashingStrategy
from r2inspect.core.file_validator import FileValidator
from r2inspect.core.result_aggregator import ResultAggregator


class _MinimalAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict:
        return {"available": True}


class _DummyHash(HashingStrategy):
    def __init__(
        self, filepath: str, *, library_available: bool = True, hash_error: str | None = None
    ):
        super().__init__(filepath=filepath, min_file_size=1)
        self._library_available = library_available
        self._hash_error = hash_error

    def _get_hash_type(self) -> str:
        return "dummy"

    def _check_library_availability(self) -> tuple[bool, str | None]:
        return self._library_available, (None if self._library_available else "missing")

    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        if self._hash_error:
            return None, None, self._hash_error
        return "hash", "method", None

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> int | None:
        if not hash1 or not hash2:
            return None
        return 0 if hash1 == hash2 else 1

    @staticmethod
    def is_available() -> bool:
        return True


class _ExplodingHash(_DummyHash):
    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        raise RuntimeError("boom")


def test_package_inits_importable():
    assert hasattr(abstractions, "BaseAnalyzer")
    assert hasattr(core, "R2Inspector")
    assert hasattr(schemas, "AnalysisResultBase")


def test_package_main_handles_help():
    original_argv = sys.argv
    try:
        sys.argv = ["r2inspect", "--help"]
        assert package_main() == 0
    finally:
        sys.argv = original_argv


def test_base_analyzer_defaults(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello")

    analyzer = _MinimalAnalyzer(filepath=str(sample))
    analyzer._cached_category = "cached"
    assert analyzer.get_category() == "cached"
    analyzer._cached_category = None
    assert analyzer.get_category() == "unknown"

    assert "No description" in analyzer.get_description()
    assert analyzer.supports_format("PE") is True
    assert analyzer.get_supported_formats() == set()
    assert _MinimalAnalyzer.is_available() is True

    def compute():
        return {"value": 1}

    wrapped = analyzer._measure_execution_time(compute)
    result = wrapped()
    assert "execution_time" in result

    assert analyzer.get_file_size() == sample.stat().st_size
    analyzer.filepath = None
    assert analyzer.get_file_size() is None
    assert analyzer.get_file_extension() == ""
    assert analyzer.file_exists() is False
    analyzer.filepath = sample
    assert analyzer.get_file_extension() == "bin"
    assert analyzer.file_exists() is True

    missing = _MinimalAnalyzer(filepath=str(tmp_path / "missing.bin"))
    assert missing.get_file_size() is None
    assert missing.get_file_extension() == "bin"
    assert missing.file_exists() is False

    analyzer._log_debug("debug")
    analyzer._log_info("info")
    analyzer._log_warning("warn")
    analyzer._log_error("error")

    text = str(analyzer)
    assert "MinimalAnalyzer" in text and "sample.bin" in text
    assert "MinimalAnalyzer" in repr(analyzer)


def test_hashing_strategy_validation_and_errors(tmp_path):
    sample = tmp_path / "hash.bin"
    sample.write_bytes(b"1234")

    ok = _DummyHash(filepath=str(sample))
    result = ok.analyze()
    assert result["available"] is True
    assert result["hash_value"] == "hash"

    missing = _DummyHash(filepath=str(sample), library_available=False)
    result = missing.analyze()
    assert "missing" in (result["error"] or "")

    with_error = _DummyHash(filepath=str(sample), hash_error="fail")
    result = with_error.analyze()
    assert result["error"] == "fail"

    exploding = _ExplodingHash(filepath=str(sample))
    result = exploding.analyze()
    assert "Unexpected error" in (result["error"] or "")

    nonexist = _DummyHash(filepath=str(tmp_path / "nope.bin"))
    result = nonexist.analyze()
    assert "does not exist" in (result["error"] or "")

    folder = tmp_path / "folder"
    folder.mkdir()
    folder_hash = _DummyHash(filepath=str(folder))
    result = folder_hash.analyze()
    assert "not a regular file" in (result["error"] or "")

    tiny = tmp_path / "tiny.bin"
    tiny.write_bytes(b"a")
    too_large = _DummyHash(filepath=str(tiny), hash_error=None)
    too_large.max_file_size = 0
    result = too_large.analyze()
    assert result["error"] is not None


def test_hashing_strategy_permission_and_stat_error(tmp_path):
    sample = tmp_path / "perm.bin"
    sample.write_bytes(b"abcd")
    sample.chmod(0o000)
    try:
        perm = _DummyHash(filepath=str(sample))
        result = perm.analyze()
        if result["error"] is None and os.access(sample, os.R_OK):
            pytest.skip("File remained readable on this platform")
        if result["error"]:
            assert "readable" in result["error"] or "does not exist" in result["error"]
    finally:
        sample.chmod(0o644)

    class _BadFile:
        def exists(self) -> bool:
            return True

        def is_file(self) -> bool:
            return True

        def stat(self, *args, **kwargs):  # noqa: ANN001, ANN002
            raise OSError("boom")

    bad = _DummyHash(filepath=str(sample))
    bad._filepath = _BadFile()  # type: ignore[assignment]
    bad.filepath = bad._filepath  # type: ignore[assignment]
    assert "Cannot access file statistics" in (bad._validate_file() or "")

    missing = _DummyHash(filepath=str(tmp_path / "missing.bin"))
    assert missing.get_file_size() is None


def test_file_validator_paths(tmp_path):
    sample = tmp_path / "file.bin"
    sample.write_bytes(b"abcd")

    validator = FileValidator(sample)
    assert validator._file_exists() is True
    assert validator._file_size_bytes() == 4
    assert validator._file_size_mb() > 0
    assert validator.validate() is False

    small = tmp_path / "small.bin"
    small.write_bytes(b"a")
    small_validator = FileValidator(small)
    assert small_validator._is_size_valid(0) is False
    assert small_validator._is_size_valid(1) is False
    assert small_validator.validate() is False

    assert validator._within_memory_limits(10**12) is False
    assert validator._is_readable() is True

    missing = FileValidator(tmp_path / "missing.bin")
    assert missing._file_exists() is False
    assert missing.validate() is False

    folder = tmp_path / "folder"
    folder.mkdir()
    folder_validator = FileValidator(folder)
    assert folder_validator._file_exists() is False
    assert folder_validator._is_readable() is False

    from r2inspect.utils import memory_manager

    original_limits = memory_manager.global_memory_monitor.limits.max_file_size_mb
    try:
        memory_manager.configure_memory_limits(max_file_size_mb=1)
        large = tmp_path / "large.bin"
        large.write_bytes(b"0" * (2 * 1024 * 1024))
        large_validator = FileValidator(large)
        assert large_validator.validate() is False
    finally:
        memory_manager.configure_memory_limits(max_file_size_mb=original_limits)

    short = tmp_path / "short.bin"
    short.write_bytes(b"ab")
    short_validator = FileValidator(short)
    assert short_validator._is_readable() is False


def test_result_aggregator_summary_and_indicators():
    aggregator = ResultAggregator()
    analysis_results = {
        "file_info": {
            "name": "sample.bin",
            "file_type": "PE",
            "size": 123,
            "architecture": "x86",
            "md5": "md5",
            "sha256": "sha",
        },
        "pe_info": {"compilation_timestamp": "now"},
        "security": {"authenticode": False, "aslr": True},
        "packer": {"is_packed": True, "packer_type": "UPX"},
        "anti_analysis": {"anti_debug": True, "anti_vm": True},
        "imports": [{"name": "VirtualAlloc"}],
        "yara_matches": [{"rule": "Rule"}],
        "sections": [{"entropy": 7.5, "name": "UPX0"}],
        "functions": {"count": 10},
        "crypto": {"matches": ["AES"]},
        "rich_header": {
            "available": True,
            "compilers": [{"compiler_name": "VC", "build_number": 1}],
        },
    }
    summary = aggregator.generate_executive_summary(analysis_results)
    assert summary["file_overview"]["filename"] == "sample.bin"
    assert summary["security_assessment"]["is_packed"] is True
    assert summary["threat_indicators"]["yara_matches"] == 1
    assert summary["technical_details"]["functions"] == 10
    assert summary["recommendations"]

    indicators = aggregator.generate_indicators(analysis_results)
    assert indicators

    broken = {"file_info": None}
    error_summary = aggregator.generate_executive_summary(broken)
    assert "error" in error_summary
