#!/usr/bin/env python3
"""Comprehensive tests for file_validator.py validation logic."""

import os
from pathlib import Path
from unittest.mock import Mock, patch
from r2inspect.core.file_validator import FileValidator
from r2inspect.core.constants import MIN_EXECUTABLE_SIZE_BYTES, MIN_HEADER_SIZE_BYTES


def test_file_validator_init_with_string():
    validator = FileValidator("test.bin")
    assert validator.filename == "test.bin"
    assert isinstance(validator.file_path, Path)


def test_file_validator_init_with_path():
    path = Path("test.exe")
    validator = FileValidator(path)
    assert validator.filename == "test.exe"
    assert isinstance(validator.file_path, Path)


def test_file_validator_init_cached_validation():
    validator = FileValidator("test.bin")
    assert validator._validated is False
    assert validator._validation_result is False


def test_file_validator_missing_file(tmp_path):
    missing = tmp_path / "nonexistent.bin"
    validator = FileValidator(missing)
    assert validator.validate() is False


def test_file_validator_directory_instead_of_file(tmp_path):
    directory = tmp_path / "testdir"
    directory.mkdir()
    validator = FileValidator(directory)
    assert validator.validate() is False


def test_file_validator_empty_file(tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    validator = FileValidator(empty)
    assert validator.validate() is False


def test_file_validator_file_too_small(tmp_path):
    tiny = tmp_path / "tiny.bin"
    tiny.write_bytes(b"\x00" * (MIN_EXECUTABLE_SIZE_BYTES - 1))
    validator = FileValidator(tiny)
    assert validator.validate() is False


def test_file_validator_file_at_minimum_size(tmp_path):
    minimal = tmp_path / "minimal.bin"
    minimal.write_bytes(b"\x00" * MIN_EXECUTABLE_SIZE_BYTES)
    validator = FileValidator(minimal)
    assert validator.validate() is True


def test_file_validator_valid_file(tmp_path):
    valid = tmp_path / "valid.bin"
    valid.write_bytes(b"MZ" + b"\x00" * 200)
    validator = FileValidator(valid)
    assert validator.validate() is True


def test_file_validator_pe_header(tmp_path):
    pe_file = tmp_path / "pe.exe"
    pe_file.write_bytes(b"MZ" + b"\x90" * 100)
    validator = FileValidator(pe_file)
    assert validator.validate() is True


def test_file_validator_elf_header(tmp_path):
    elf_file = tmp_path / "elf.bin"
    elf_file.write_bytes(b"\x7fELF" + b"\x00" * 100)
    validator = FileValidator(elf_file)
    assert validator.validate() is True


def test_file_validator_caching_success(tmp_path):
    valid = tmp_path / "valid.bin"
    valid.write_bytes(b"MZ" + b"\x00" * 100)
    validator = FileValidator(valid)
    
    result1 = validator.validate()
    result2 = validator.validate()
    
    assert result1 is True
    assert result2 is True
    assert validator._validated is True


def test_file_validator_caching_failure(tmp_path):
    missing = tmp_path / "missing.bin"
    validator = FileValidator(missing)
    
    result1 = validator.validate()
    result2 = validator.validate()
    
    assert result1 is False
    assert result2 is False
    assert validator._validated is True


def test_file_exists_method(tmp_path):
    existing = tmp_path / "exists.bin"
    existing.write_bytes(b"test")
    validator = FileValidator(existing)
    assert validator._file_exists() is True


def test_file_exists_method_missing(tmp_path):
    missing = tmp_path / "missing.bin"
    validator = FileValidator(missing)
    assert validator._file_exists() is False


def test_file_exists_method_directory(tmp_path):
    directory = tmp_path / "dir"
    directory.mkdir()
    validator = FileValidator(directory)
    assert validator._file_exists() is False


def test_file_size_bytes(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"A" * 1024)
    validator = FileValidator(sample)
    assert validator._file_size_bytes() == 1024


def test_file_size_mb(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"A" * (1024 * 1024))
    validator = FileValidator(sample)
    assert validator._file_size_mb() == 1.0


def test_file_size_mb_small_file(tmp_path):
    sample = tmp_path / "small.bin"
    sample.write_bytes(b"A" * 512)
    validator = FileValidator(sample)
    size_mb = validator._file_size_mb()
    assert size_mb < 0.001


def test_is_size_valid_zero_size(tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    validator = FileValidator(empty)
    assert validator._is_size_valid(0) is False


def test_is_size_valid_too_small(tmp_path):
    tiny = tmp_path / "tiny.bin"
    tiny.write_bytes(b"x")
    validator = FileValidator(tiny)
    assert validator._is_size_valid(1) is False


def test_is_size_valid_minimum(tmp_path):
    minimal = tmp_path / "minimal.bin"
    minimal.write_bytes(b"x" * MIN_EXECUTABLE_SIZE_BYTES)
    validator = FileValidator(minimal)
    assert validator._is_size_valid(MIN_EXECUTABLE_SIZE_BYTES) is True


def test_is_size_valid_large(tmp_path):
    large = tmp_path / "large.bin"
    validator = FileValidator(large)
    assert validator._is_size_valid(10 * 1024 * 1024) is True


def test_within_memory_limits_normal_file(tmp_path):
    normal = tmp_path / "normal.bin"
    normal.write_bytes(b"A" * (1024 * 1024))
    validator = FileValidator(normal)
    assert validator._within_memory_limits(1024 * 1024) is True


def test_within_memory_limits_small_file(tmp_path):
    small = tmp_path / "small.bin"
    small.write_bytes(b"A" * 1024)
    validator = FileValidator(small)
    assert validator._within_memory_limits(1024) is True


@patch("r2inspect.core.file_validator.check_memory_limits")
def test_within_memory_limits_exceeds_limit(mock_check, tmp_path):
    mock_check.return_value = False
    large = tmp_path / "large.bin"
    validator = FileValidator(large)
    result = validator._within_memory_limits(1000 * 1024 * 1024)
    assert result is False


@patch("r2inspect.core.file_validator.check_memory_limits")
def test_within_memory_limits_within_limit(mock_check, tmp_path):
    mock_check.return_value = True
    normal = tmp_path / "normal.bin"
    validator = FileValidator(normal)
    result = validator._within_memory_limits(10 * 1024 * 1024)
    assert result is True


def test_is_readable_valid_file(tmp_path):
    readable = tmp_path / "readable.bin"
    readable.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
    validator = FileValidator(readable)
    assert validator._is_readable() is True


def test_is_readable_tiny_header(tmp_path):
    tiny = tmp_path / "tiny.bin"
    tiny.write_bytes(b"MZ")
    validator = FileValidator(tiny)
    assert validator._is_readable() is False


def test_is_readable_three_bytes(tmp_path):
    tiny = tmp_path / "three.bin"
    tiny.write_bytes(b"MZA")
    validator = FileValidator(tiny)
    assert validator._is_readable() is False


def test_is_readable_four_bytes(tmp_path):
    four = tmp_path / "four.bin"
    four.write_bytes(b"MZ\x90\x00")
    validator = FileValidator(four)
    assert validator._is_readable() is True


def test_is_readable_permission_error(tmp_path):
    unreadable = tmp_path / "unreadable.bin"
    unreadable.write_bytes(b"MZ" + b"\x00" * 100)
    os.chmod(unreadable, 0o000)
    
    validator = FileValidator(unreadable)
    try:
        result = validator._is_readable()
        assert result is False
    finally:
        os.chmod(unreadable, 0o644)


def test_validate_full_flow_valid(tmp_path):
    valid = tmp_path / "valid.exe"
    valid.write_bytes(b"MZ" + b"\x00" * 200)
    validator = FileValidator(valid)
    assert validator.validate() is True


def test_validate_full_flow_missing():
    validator = FileValidator("/nonexistent/path/file.bin")
    assert validator.validate() is False


def test_validate_full_flow_too_small(tmp_path):
    small = tmp_path / "small.bin"
    small.write_bytes(b"MZ")
    validator = FileValidator(small)
    assert validator.validate() is False


@patch("r2inspect.core.file_validator.check_memory_limits")
def test_validate_full_flow_memory_limit(mock_check, tmp_path):
    mock_check.return_value = False
    large = tmp_path / "large.bin"
    large.write_bytes(b"MZ" + b"\x00" * 1000)
    validator = FileValidator(large)
    assert validator.validate() is False


def test_validate_stops_early_on_missing(tmp_path):
    missing = tmp_path / "missing.bin"
    validator = FileValidator(missing)
    
    with patch.object(validator, '_file_size_bytes') as mock_size:
        validator.validate()
        mock_size.assert_not_called()


def test_validate_stops_early_on_size_invalid(tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    validator = FileValidator(empty)
    
    with patch.object(validator, '_is_readable') as mock_readable:
        validator.validate()
        mock_readable.assert_not_called()


@patch("r2inspect.core.file_validator.check_memory_limits")
def test_validate_stops_early_on_memory_limit(mock_check, tmp_path):
    mock_check.return_value = False
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 1000)
    validator = FileValidator(sample)
    
    with patch.object(validator, '_is_readable') as mock_readable:
        validator.validate()
        mock_readable.assert_not_called()


def test_validator_with_relative_path(tmp_path):
    import os
    old_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        sample = Path("sample.bin")
        sample.write_bytes(b"MZ" + b"\x00" * 100)
        
        validator = FileValidator("sample.bin")
        assert validator.validate() is True
    finally:
        os.chdir(old_cwd)


def test_validator_with_absolute_path(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 100)
    
    validator = FileValidator(str(sample.absolute()))
    assert validator.validate() is True


def test_validator_with_unicode_filename(tmp_path):
    unicode_file = tmp_path / "тест.bin"
    unicode_file.write_bytes(b"MZ" + b"\x00" * 100)
    
    validator = FileValidator(unicode_file)
    assert validator.validate() is True


def test_validator_with_spaces_in_filename(tmp_path):
    spaced = tmp_path / "my file.bin"
    spaced.write_bytes(b"MZ" + b"\x00" * 100)
    
    validator = FileValidator(spaced)
    assert validator.validate() is True


def test_validator_filename_string_representation(tmp_path):
    sample = tmp_path / "test.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 100)
    
    validator = FileValidator(sample)
    assert isinstance(validator.filename, str)
    assert "test.exe" in validator.filename


def test_validator_file_path_is_path_object(tmp_path):
    sample = tmp_path / "test.bin"
    validator = FileValidator(sample)
    assert isinstance(validator.file_path, Path)


def test_validator_multiple_validations_cached(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 100)
    validator = FileValidator(sample)
    
    with patch.object(validator, '_file_exists', wraps=validator._file_exists) as mock_exists:
        validator.validate()
        validator.validate()
        validator.validate()
        
        assert mock_exists.call_count == 1


def test_validator_different_files_different_results(tmp_path):
    valid = tmp_path / "valid.bin"
    valid.write_bytes(b"MZ" + b"\x00" * 100)
    
    invalid = tmp_path / "invalid.bin"
    
    validator1 = FileValidator(valid)
    validator2 = FileValidator(invalid)
    
    assert validator1.validate() is True
    assert validator2.validate() is False


def test_validator_minimum_header_size_boundary(tmp_path):
    boundary = tmp_path / "boundary.bin"
    boundary.write_bytes(b"MZ\x90\x00" + b"\x00" * (MIN_EXECUTABLE_SIZE_BYTES - 4))
    validator = FileValidator(boundary)
    assert validator.validate() is True


def test_validator_size_exact_minimum_executable(tmp_path):
    exact = tmp_path / "exact.bin"
    exact.write_bytes(b"MZ\x90\x00" + b"\x00" * (MIN_EXECUTABLE_SIZE_BYTES - 4))
    validator = FileValidator(exact)
    assert validator.validate() is True


def test_validator_size_one_byte_below_minimum(tmp_path):
    below = tmp_path / "below.bin"
    below.write_bytes(b"MZ\x90\x00" + b"\x00" * (MIN_EXECUTABLE_SIZE_BYTES - 5))
    validator = FileValidator(below)
    assert validator.validate() is False


def test_validator_large_valid_file(tmp_path):
    large = tmp_path / "large.bin"
    large.write_bytes(b"MZ" + b"\x00" * (10 * 1024 * 1024))
    validator = FileValidator(large)
    assert validator.validate() is True


def test_validator_file_info_methods(tmp_path):
    sample = tmp_path / "sample.bin"
    data = b"MZ" + b"\x00" * 1024
    sample.write_bytes(data)
    
    validator = FileValidator(sample)
    
    assert validator._file_size_bytes() == len(data)
    assert validator._file_size_mb() == len(data) / (1024 * 1024)


def test_validator_validation_result_persists(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 100)
    
    validator = FileValidator(sample)
    assert validator._validation_result is False
    validator.validate()
    assert validator._validation_result is True


def test_validator_symlink_to_valid_file(tmp_path):
    original = tmp_path / "original.bin"
    original.write_bytes(b"MZ" + b"\x00" * 100)
    
    link = tmp_path / "link.bin"
    link.symlink_to(original)
    
    validator = FileValidator(link)
    assert validator.validate() is True


def test_validator_header_read_exactly_min_bytes(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ\x90\x00" + b"A" * 100)
    
    validator = FileValidator(sample)
    assert validator._is_readable() is True
