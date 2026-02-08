from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from r2inspect.__main__ import main as package_main
from r2inspect.config import Config
from r2inspect.config_store import ConfigStore
from r2inspect.core.file_validator import FileValidator
from r2inspect.core.result_aggregator import ResultAggregator
from r2inspect.utils import hashing as hashing_utils
from r2inspect.utils.error_handler import (
    ErrorCategory,
    ErrorClassifier,
    ErrorSeverity,
    error_handler,
    get_error_stats,
    reset_error_stats,
    safe_execute,
)


def test_package_main_returns_exit_code() -> None:
    original_argv = sys.argv[:]
    try:
        sys.argv = ["r2inspect", "--help"]
        assert package_main() == 0
    finally:
        sys.argv = original_argv


def test_config_roundtrip_and_overrides(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config = Config(config_path=str(config_path))
    assert config_path.exists()

    config.apply_overrides({"general": {"verbose": True}})
    config.set("output", "json_indent", 4)
    config.set("custom", "flag", True)

    data = config.to_dict()
    assert data["general"]["verbose"] is True
    assert data["output"]["json_indent"] == 4
    assert data["custom"]["flag"] is True
    assert os.path.isabs(config.get_yara_rules_path())
    assert config.is_virustotal_enabled() is False

    cloned = config.from_dict({"general": {"max_strings": 10}})
    assert cloned.to_dict()["general"]["max_strings"] == 10


def test_config_invalid_values_fallback(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    bad_payload = {"pipeline": "bad"}
    config_path.write_text(json.dumps(bad_payload))

    config = Config(config_path=str(config_path))
    data = config.to_dict()
    assert data["pipeline"] == "bad"
    assert isinstance(config.typed_config.pipeline.max_workers, int)


def test_config_store_load_save(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    payload = {"hello": "world"}
    ConfigStore.save(str(config_path), payload)
    assert ConfigStore.load(str(config_path)) == payload

    bad_path = tmp_path / "bad.json"
    bad_path.write_text("{")
    assert ConfigStore.load(str(bad_path)) is None


def test_file_validator_paths(tmp_path: Path) -> None:
    empty_path = tmp_path / "empty.bin"
    empty_path.write_bytes(b"")
    assert FileValidator(empty_path).validate() is False

    small_path = tmp_path / "small.bin"
    small_path.write_bytes(b"A" * 8)
    assert FileValidator(small_path).validate() is False

    ok_path = tmp_path / "ok.bin"
    ok_path.write_bytes(b"A" * 64)
    assert FileValidator(ok_path).validate() is True


def test_result_aggregator_indicators_and_summary() -> None:
    aggregator = ResultAggregator()
    analysis_results = {
        "file_info": {"name": "sample.bin", "file_type": "PE", "size": 10},
        "pe_info": {"compilation_timestamp": "2024-01-01"},
        "security": {"authenticode": False, "aslr": True},
        "packer": {"is_packed": True, "packer_type": "UPX"},
        "anti_analysis": {"anti_debug": True},
        "imports": [{"name": "VirtualAlloc"}],
        "yara_matches": [{"rule": "demo"}],
        "sections": [{"name": ".text", "entropy": 7.5}],
        "functions": {"count": 1},
        "crypto": {"matches": ["AES"]},
        "rich_header": {
            "available": True,
            "compilers": [{"compiler_name": "MSVC", "build_number": 1234}],
        },
    }

    indicators = aggregator.generate_indicators(analysis_results)
    assert indicators

    summary = aggregator.generate_executive_summary(analysis_results)
    assert summary["file_overview"]["filename"] == "sample.bin"
    assert summary["security_assessment"]["packer_type"] == "UPX"

    bad_summary = aggregator.generate_executive_summary({"crypto": None})
    assert "error" in bad_summary


def test_hashing_utils(tmp_path: Path) -> None:
    sample_path = tmp_path / "sample.bin"
    sample_path.write_bytes(b"abc" * 10)

    hashes = hashing_utils.calculate_hashes(str(sample_path))
    assert hashes["md5"]
    assert hashes["sha1"]
    assert hashes["sha256"]
    assert hashes["sha512"]

    assert hashing_utils.calculate_hashes(str(tmp_path / "missing.bin"))["md5"] == ""

    imphash = hashing_utils.calculate_imphash([{"library": "KERNEL32.dll", "name": "CreateFileA"}])
    assert isinstance(imphash, str)

    assert hashing_utils.calculate_imphash([]) is None
    ssdeep = hashing_utils.calculate_ssdeep(str(sample_path))
    assert ssdeep is None or isinstance(ssdeep, str)


def test_error_handler_classification_and_recovery() -> None:
    reset_error_stats()

    info = ErrorClassifier.classify(
        MemoryError("boom"), {"file_size_mb": 200, "memory_cleanup_available": True}
    )
    assert info.category == ErrorCategory.MEMORY
    assert info.severity in {ErrorSeverity.HIGH, ErrorSeverity.CRITICAL}

    def raises_value_error() -> None:
        raise ValueError("bad")

    recovered = safe_execute(raises_value_error, fallback_result="fallback")
    assert recovered == "fallback"

    @error_handler(
        category=ErrorCategory.ANALYSIS,
        severity=ErrorSeverity.CRITICAL,
        fallback_result={"error": "failed"},
    )
    def raises_memory_error() -> None:
        raise MemoryError("oom")

    with pytest.raises(MemoryError):
        raises_memory_error()

    stats = get_error_stats()
    assert "total_errors" in stats
