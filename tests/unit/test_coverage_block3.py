from __future__ import annotations

import hashlib
from pathlib import Path

from r2inspect.core.constants import MIN_EXECUTABLE_SIZE_BYTES
from r2inspect.core.file_validator import FileValidator
from r2inspect.utils import hashing
from r2inspect.utils.memory_manager import configure_memory_limits, global_memory_monitor


def test_calculate_hashes_success_and_missing(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc123")

    expected = {
        "md5": hashlib.md5(b"abc123", usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(b"abc123", usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(b"abc123").hexdigest(),
        "sha512": hashlib.sha512(b"abc123").hexdigest(),
    }

    hashes = hashing.calculate_hashes(str(sample))
    assert hashes == expected

    missing = hashing.calculate_hashes(str(tmp_path / "missing.bin"))
    assert all(value == "" for value in missing.values())


def test_calculate_hashes_error_path(tmp_path: Path) -> None:
    hashes = hashing.calculate_hashes(str(tmp_path))
    assert all(value.startswith("Error:") for value in hashes.values())


def test_calculate_imphash_variations() -> None:
    imports = [
        {"library": "KERNEL32.DLL", "name": "CreateFileA"},
        {"library": "USER32.dll", "name": "MessageBoxA"},
        {"library": "", "name": "Ignore"},
        {"library": "ADVAPI32.dll", "name": ""},
    ]
    import_string = "kernel32.dll.createfilea,user32.dll.messageboxa"
    expected = hashlib.md5(import_string.encode(), usedforsecurity=False).hexdigest()

    assert hashing.calculate_imphash(imports) == expected
    assert hashing.calculate_imphash([]) is None
    assert hashing.calculate_imphash([{"library": "", "name": ""}]) is None


def test_file_validator_basic_paths(tmp_path: Path) -> None:
    missing = FileValidator(tmp_path / "missing.bin")
    assert missing.validate() is False

    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    assert FileValidator(empty).validate() is False

    tiny = tmp_path / "tiny.bin"
    tiny.write_bytes(b"x" * (MIN_EXECUTABLE_SIZE_BYTES - 1))
    assert FileValidator(tiny).validate() is False


def test_file_validator_size_and_header_checks(tmp_path: Path) -> None:
    file_path = tmp_path / "valid.bin"
    file_path.write_bytes(b"A" * (MIN_EXECUTABLE_SIZE_BYTES + 1))
    validator = FileValidator(file_path)
    assert validator._file_size_bytes() == file_path.stat().st_size
    assert validator._file_size_mb() > 0

    # Force memory limit failure with a tiny limit
    original_limit = global_memory_monitor.limits.max_file_size_mb
    try:
        configure_memory_limits(max_file_size_mb=0)
        assert validator._within_memory_limits(file_path.stat().st_size) is False
    finally:
        configure_memory_limits(max_file_size_mb=original_limit)

    # _is_readable should succeed with a valid header
    assert validator._is_readable() is True

    # Call _is_readable on a file with a tiny header to hit the short-read branch
    small_header = tmp_path / "small_header.bin"
    small_header.write_bytes(b"XYZ")
    assert FileValidator(small_header)._is_readable() is False
