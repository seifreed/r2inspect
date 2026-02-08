from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.core.file_validator import FileValidator
from r2inspect.utils import memory_manager


def test_file_validator_missing_and_empty(tmp_path: Path):
    missing = tmp_path / "missing.bin"
    assert FileValidator(str(missing)).validate() is False

    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    assert FileValidator(str(empty)).validate() is False


def test_file_validator_too_small_and_header_short(tmp_path: Path):
    tiny = tmp_path / "tiny.bin"
    tiny.write_bytes(b"abc")
    validator = FileValidator(str(tiny))
    assert validator._is_readable() is False
    assert validator._is_size_valid(tiny.stat().st_size) is False


def test_file_validator_memory_limit(tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"A" * 64)

    limits = memory_manager.global_memory_monitor.limits
    original_max = limits.max_file_size_mb
    try:
        memory_manager.configure_memory_limits(max_file_size_mb=0)
        assert FileValidator(str(sample)).validate() is False
    finally:
        memory_manager.configure_memory_limits(max_file_size_mb=original_max)


def test_file_validator_exception_path(tmp_path: Path):
    class ExplodingValidator(FileValidator):
        def _file_exists(self) -> bool:
            raise RuntimeError("boom")

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"A" * 64)
    assert ExplodingValidator(str(sample)).validate() is False


def test_file_validator_unreadable(tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"A" * 64)
    sample.chmod(0o000)
    try:
        validator = FileValidator(str(sample))
        assert validator._is_readable() is False
    finally:
        sample.chmod(0o600)
