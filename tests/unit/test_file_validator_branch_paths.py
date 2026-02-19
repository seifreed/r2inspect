from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.core.file_validator import FileValidator


def test_validate_returns_cached_result_on_second_call(tmp_path: Path) -> None:
    path = tmp_path / "valid.bin"
    path.write_bytes(b"\x7fELF" + b"\x00" * 60)
    validator = FileValidator(str(path))
    r1 = validator.validate()
    r2 = validator.validate()
    assert r1 == r2
    assert validator._validated is True


def test_validate_missing_file_returns_false() -> None:
    validator = FileValidator("/nonexistent/file.bin")
    assert validator.validate() is False


def test_validate_directory_returns_false(tmp_path: Path) -> None:
    validator = FileValidator(str(tmp_path))
    result = validator.validate()
    assert result is False


def test_validate_empty_file_returns_false(tmp_path: Path) -> None:
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    validator = FileValidator(str(empty))
    assert validator.validate() is False


def test_validate_too_small_file_returns_false(tmp_path: Path) -> None:
    tiny = tmp_path / "tiny.bin"
    tiny.write_bytes(b"\x00")
    validator = FileValidator(str(tiny))
    result = validator.validate()
    assert result is False


def test_validate_valid_file_returns_true(tmp_path: Path) -> None:
    path = tmp_path / "valid.bin"
    path.write_bytes(b"\x7fELF" + b"\x00" * 256)
    validator = FileValidator(str(path))
    result = validator.validate()
    assert result is True


def test_file_exists_nonexistent_returns_false() -> None:
    validator = FileValidator("/no/such/file.bin")
    assert validator._file_exists() is False


def test_file_exists_directory_returns_false(tmp_path: Path) -> None:
    validator = FileValidator(str(tmp_path))
    assert validator._file_exists() is False


def test_file_exists_valid_file_returns_true(tmp_path: Path) -> None:
    path = tmp_path / "file.bin"
    path.write_bytes(b"x" * 10)
    validator = FileValidator(str(path))
    assert validator._file_exists() is True


def test_is_size_valid_zero_returns_false(tmp_path: Path) -> None:
    validator = FileValidator(str(tmp_path / "f.bin"))
    assert validator._is_size_valid(0) is False


def test_is_size_valid_tiny_returns_false(tmp_path: Path) -> None:
    validator = FileValidator(str(tmp_path / "f.bin"))
    assert validator._is_size_valid(1) is False


def test_is_readable_short_header_returns_false(tmp_path: Path) -> None:
    path = tmp_path / "short.bin"
    path.write_bytes(b"\x00\x01")
    validator = FileValidator(str(path))
    assert validator._is_readable() is False


def test_is_readable_valid_header_returns_true(tmp_path: Path) -> None:
    path = tmp_path / "full.bin"
    path.write_bytes(b"\x7fELF\x00" * 20)
    validator = FileValidator(str(path))
    assert validator._is_readable() is True


def test_file_size_bytes(tmp_path: Path) -> None:
    path = tmp_path / "sized.bin"
    path.write_bytes(b"x" * 128)
    validator = FileValidator(str(path))
    assert validator._file_size_bytes() == 128


def test_file_size_mb(tmp_path: Path) -> None:
    path = tmp_path / "sized.bin"
    path.write_bytes(b"x" * 1024 * 1024)
    validator = FileValidator(str(path))
    assert abs(validator._file_size_mb() - 1.0) < 0.01
