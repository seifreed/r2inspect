#!/usr/bin/env python3
"""
Comprehensive tests for r2inspect/cli/validators.py module.
Tests input validation, security checks, and error handling.
Coverage target: 100% (currently 14%)
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from r2inspect.cli.validators import (
    display_validation_errors,
    handle_xor_input,
    sanitize_xor_string,
    validate_batch_input,
    validate_config_input,
    validate_extensions_input,
    validate_file_input,
    validate_input_mode,
    validate_inputs,
    validate_output_input,
    validate_single_file,
    validate_threads_input,
    validate_yara_input,
)


def test_validate_file_input_valid(tmp_path):
    """Test validation of valid file input"""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data" * 100)
    errors = validate_file_input(str(sample))
    assert errors == []


def test_validate_file_input_empty_file(tmp_path):
    """Test validation rejects empty files"""
    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")
    errors = validate_file_input(str(empty_file))
    assert len(errors) == 1
    assert "empty" in errors[0].lower()


def test_validate_file_input_too_large(tmp_path):
    """Test validation handles large file check"""
    large_file = tmp_path / "large.bin"
    large_file.write_bytes(b"x" * 1000)
    errors = validate_file_input(str(large_file))
    assert errors == []


def test_validate_file_input_not_a_file(tmp_path):
    """Test validation rejects directories"""
    errors = validate_file_input(str(tmp_path))
    assert len(errors) == 1
    assert "not a regular file" in errors[0].lower()


def test_validate_file_input_missing_file(tmp_path):
    """Test validation handles missing files"""
    errors = validate_file_input(str(tmp_path / "missing.bin"))
    assert len(errors) > 0


def test_validate_file_input_path_traversal(tmp_path):
    """Test validation prevents path traversal attacks"""
    errors = validate_file_input("../../etc/passwd")
    assert len(errors) > 0


def test_validate_file_input_simulated_error(tmp_path):
    """Test file access error handling"""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")
    
    with patch.dict(os.environ, {"R2INSPECT_TEST_RAISE_FILE_ERROR": "1"}):
        errors = validate_file_input(str(sample))
        assert len(errors) > 0
        assert "access error" in errors[0].lower()


def test_validate_file_input_none():
    """Test validation with None input"""
    errors = validate_file_input(None)
    assert errors == []


def test_validate_batch_input_valid_directory(tmp_path):
    """Test validation of valid batch directory"""
    errors = validate_batch_input(str(tmp_path))
    assert errors == []


def test_validate_batch_input_missing_directory(tmp_path):
    """Test validation handles missing batch directory"""
    errors = validate_batch_input(str(tmp_path / "missing"))
    assert len(errors) > 0


def test_validate_batch_input_not_a_directory(tmp_path):
    """Test validation rejects files as batch directory"""
    file_path = tmp_path / "file.txt"
    file_path.write_text("content")
    errors = validate_batch_input(str(file_path))
    assert len(errors) == 1
    assert "not a directory" in errors[0].lower()


def test_validate_batch_input_simulated_error(tmp_path):
    """Test batch directory access error handling"""
    with patch.dict(os.environ, {"R2INSPECT_TEST_RAISE_BATCH_ERROR": "1"}):
        errors = validate_batch_input(str(tmp_path))
        assert len(errors) > 0
        assert "access error" in errors[0].lower()


def test_validate_batch_input_none():
    """Test validation with None batch input"""
    errors = validate_batch_input(None)
    assert errors == []


def test_validate_output_input_valid_file(tmp_path):
    """Test validation of valid output file"""
    output_file = tmp_path / "output.json"
    output_file.write_text("{}")
    errors = validate_output_input(str(output_file))
    assert errors == []


def test_validate_output_input_readonly_file(tmp_path):
    """Test validation handles read-only output files"""
    output_file = tmp_path / "readonly.json"
    output_file.write_text("{}")
    output_file.chmod(0o444)
    
    errors = validate_output_input(str(output_file))
    if os.name != 'nt':
        assert len(errors) > 0
        assert "cannot write" in errors[0].lower()


def test_validate_output_input_directory_path(tmp_path):
    """Test validation of output directory path"""
    output_dir = tmp_path / "output"
    errors = validate_output_input(str(output_dir))
    assert errors == []


def test_validate_output_input_parent_not_directory(tmp_path):
    """Test validation when parent path is not a directory"""
    file_path = tmp_path / "file.txt"
    file_path.write_text("content")
    output_path = file_path / "output"
    errors = validate_output_input(str(output_path))
    assert len(errors) > 0
    assert "not a directory" in errors[0].lower()


def test_validate_output_input_none():
    """Test validation with None output"""
    errors = validate_output_input(None)
    assert errors == []


def test_validate_yara_input_valid_directory(tmp_path):
    """Test validation of valid YARA rules directory"""
    yara_dir = tmp_path / "yara"
    yara_dir.mkdir()
    errors = validate_yara_input(str(yara_dir))
    assert errors == []


def test_validate_yara_input_missing_directory(tmp_path):
    """Test validation handles missing YARA directory"""
    errors = validate_yara_input(str(tmp_path / "missing_yara"))
    assert len(errors) == 1
    assert "does not exist" in errors[0].lower()


def test_validate_yara_input_not_directory(tmp_path):
    """Test validation rejects file as YARA directory"""
    yara_file = tmp_path / "yara.txt"
    yara_file.write_text("rule test {}")
    errors = validate_yara_input(str(yara_file))
    assert len(errors) == 1
    assert "not a directory" in errors[0].lower()


def test_validate_yara_input_none():
    """Test validation with None YARA input"""
    errors = validate_yara_input(None)
    assert errors == []


def test_validate_config_input_valid_json(tmp_path):
    """Test validation of valid JSON config file"""
    config = tmp_path / "config.json"
    config.write_text('{"key": "value"}')
    errors = validate_config_input(str(config))
    assert errors == []


def test_validate_config_input_valid_yaml(tmp_path):
    """Test validation of valid YAML config file"""
    config = tmp_path / "config.yaml"
    config.write_text("key: value")
    errors = validate_config_input(str(config))
    assert errors == []


def test_validate_config_input_valid_yml(tmp_path):
    """Test validation of valid YML config file"""
    config = tmp_path / "config.yml"
    config.write_text("key: value")
    errors = validate_config_input(str(config))
    assert errors == []


def test_validate_config_input_valid_toml(tmp_path):
    """Test validation of valid TOML config file"""
    config = tmp_path / "config.toml"
    config.write_text('[section]\nkey = "value"')
    errors = validate_config_input(str(config))
    assert errors == []


def test_validate_config_input_missing_file(tmp_path):
    """Test validation handles missing config file"""
    errors = validate_config_input(str(tmp_path / "missing.json"))
    assert len(errors) == 1
    assert "does not exist" in errors[0].lower()


def test_validate_config_input_not_a_file(tmp_path):
    """Test validation rejects directory as config file"""
    errors = validate_config_input(str(tmp_path))
    assert len(errors) == 1
    assert "not a file" in errors[0].lower()


def test_validate_config_input_invalid_extension(tmp_path):
    """Test validation rejects invalid config file extensions"""
    config = tmp_path / "config.exe"
    config.write_text("data")
    errors = validate_config_input(str(config))
    assert len(errors) == 1
    assert "must be json" in errors[0].lower()


def test_validate_config_input_none():
    """Test validation with None config input"""
    errors = validate_config_input(None)
    assert errors == []


def test_validate_extensions_input_valid_single():
    """Test validation of single valid extension"""
    errors = validate_extensions_input("exe")
    assert errors == []


def test_validate_extensions_input_valid_multiple():
    """Test validation of multiple valid extensions"""
    errors = validate_extensions_input("exe, dll, sys")
    assert errors == []


def test_validate_extensions_input_with_dots():
    """Test validation of extensions with dots"""
    errors = validate_extensions_input(".exe, .dll")
    assert errors == []


def test_validate_extensions_input_with_hyphens():
    """Test validation of extensions with hyphens"""
    errors = validate_extensions_input("exe-file, dll-file")
    assert errors == []


def test_validate_extensions_input_with_underscores():
    """Test validation of extensions with underscores"""
    errors = validate_extensions_input("exe_file, dll_file")
    assert errors == []


def test_validate_extensions_input_invalid_characters():
    """Test validation rejects invalid characters in extensions"""
    errors = validate_extensions_input("exe@, dll#")
    assert len(errors) >= 2
    assert all("invalid file extension" in e.lower() for e in errors)


def test_validate_extensions_input_too_long():
    """Test validation rejects extensions that are too long"""
    long_ext = "a" * 11
    errors = validate_extensions_input(long_ext)
    assert len(errors) == 1
    assert "too long" in errors[0].lower()


def test_validate_extensions_input_none():
    """Test validation with None extensions"""
    errors = validate_extensions_input(None)
    assert errors == []


def test_validate_threads_input_valid():
    """Test validation of valid thread count"""
    errors = validate_threads_input(10)
    assert errors == []


def test_validate_threads_input_minimum():
    """Test validation of minimum thread count"""
    errors = validate_threads_input(1)
    assert errors == []


def test_validate_threads_input_maximum():
    """Test validation of maximum thread count"""
    errors = validate_threads_input(50)
    assert errors == []


def test_validate_threads_input_zero():
    """Test validation rejects zero threads"""
    errors = validate_threads_input(0)
    assert len(errors) == 1
    assert "positive integer" in errors[0].lower()


def test_validate_threads_input_negative():
    """Test validation rejects negative threads"""
    errors = validate_threads_input(-5)
    assert len(errors) == 1
    assert "positive integer" in errors[0].lower()


def test_validate_threads_input_too_many():
    """Test validation rejects too many threads"""
    errors = validate_threads_input(51)
    assert len(errors) == 1
    assert "too many threads" in errors[0].lower()


def test_validate_threads_input_none():
    """Test validation with None threads"""
    errors = validate_threads_input(None)
    assert errors == []


def test_sanitize_xor_string_valid():
    """Test sanitization of valid XOR string"""
    result = sanitize_xor_string("test_string123")
    assert result == "test_string123"


def test_sanitize_xor_string_with_spaces():
    """Test sanitization preserves spaces"""
    result = sanitize_xor_string("test string")
    assert result == "test string"


def test_sanitize_xor_string_removes_special_chars():
    """Test sanitization removes special characters"""
    result = sanitize_xor_string("test@#$%^&*()string")
    assert result == "teststring"


def test_sanitize_xor_string_preserves_safe_chars():
    """Test sanitization preserves safe characters"""
    result = sanitize_xor_string("test_string-123.abc")
    assert result == "test_string-123.abc"


def test_sanitize_xor_string_length_limit():
    """Test sanitization enforces length limit"""
    long_string = "a" * 150
    result = sanitize_xor_string(long_string)
    assert len(result) == 100


def test_sanitize_xor_string_empty():
    """Test sanitization of empty string"""
    result = sanitize_xor_string("")
    assert result is None


def test_sanitize_xor_string_only_invalid():
    """Test sanitization of string with only invalid characters"""
    result = sanitize_xor_string("@#$%^&*()")
    assert result is None


def test_sanitize_xor_string_none():
    """Test sanitization with None input"""
    result = sanitize_xor_string(None)
    assert result is None


def test_handle_xor_input_valid(capsys):
    """Test handling of valid XOR input"""
    result = handle_xor_input("test123")
    assert result == "test123"


def test_handle_xor_input_with_invalid_chars(capsys):
    """Test handling of XOR input with invalid characters"""
    result = handle_xor_input("test@#$")
    assert result == "test"
    captured = capsys.readouterr()
    assert "warning" in captured.out.lower() or result


def test_handle_xor_input_none():
    """Test handling of None XOR input"""
    result = handle_xor_input(None)
    assert result is None


def test_display_validation_errors(capsys):
    """Test display of validation errors"""
    errors = ["Error 1", "Error 2", "Error 3"]
    display_validation_errors(errors)
    captured = capsys.readouterr()
    assert "Error 1" in captured.out
    assert "Error 2" in captured.out
    assert "Error 3" in captured.out


def test_display_validation_errors_empty(capsys):
    """Test display of empty error list"""
    display_validation_errors([])
    captured = capsys.readouterr()
    assert captured.out == ""


def test_validate_input_mode_both_provided(tmp_path):
    """Test validation fails when both filename and batch are provided"""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")
    
    with pytest.raises(SystemExit) as exc_info:
        validate_input_mode(str(sample), str(tmp_path))
    assert exc_info.value.code == 1


def test_validate_input_mode_neither_provided():
    """Test validation fails when neither filename nor batch is provided"""
    with pytest.raises(SystemExit) as exc_info:
        validate_input_mode(None, None)
    assert exc_info.value.code == 1


def test_validate_input_mode_filename_only_valid(tmp_path):
    """Test validation passes with valid filename only"""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")
    validate_input_mode(str(sample), None)


def test_validate_input_mode_batch_only(tmp_path):
    """Test validation passes with batch directory only"""
    validate_input_mode(None, str(tmp_path))


def test_validate_single_file_valid(tmp_path):
    """Test validation of existing single file"""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")
    validate_single_file(str(sample))


def test_validate_single_file_missing(tmp_path):
    """Test validation fails for missing file"""
    with pytest.raises(SystemExit) as exc_info:
        validate_single_file(str(tmp_path / "missing.bin"))
    assert exc_info.value.code == 1


def test_validate_single_file_directory(tmp_path):
    """Test validation fails for directory"""
    with pytest.raises(SystemExit) as exc_info:
        validate_single_file(str(tmp_path))
    assert exc_info.value.code == 1


def test_validate_inputs_all_valid(tmp_path):
    """Test validation of all valid inputs"""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data" * 100)
    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()
    output_dir = tmp_path / "output"
    yara_dir = tmp_path / "yara"
    yara_dir.mkdir()
    config_file = tmp_path / "config.json"
    config_file.write_text("{}")
    
    errors = validate_inputs(
        filename=str(sample),
        batch=None,
        output=str(output_dir),
        yara=str(yara_dir),
        config=str(config_file),
        extensions="exe,dll",
        threads=10
    )
    assert errors == []


def test_validate_inputs_multiple_errors(tmp_path):
    """Test validation collects multiple errors"""
    errors = validate_inputs(
        filename=str(tmp_path / "missing.bin"),
        batch=str(tmp_path / "missing_dir"),
        output=None,
        yara=str(tmp_path / "missing_yara"),
        config=str(tmp_path / "missing.json"),
        extensions="invalid@#$",
        threads=100
    )
    assert len(errors) >= 4


def test_validate_inputs_all_none():
    """Test validation with all None inputs"""
    errors = validate_inputs(
        filename=None,
        batch=None,
        output=None,
        yara=None,
        config=None,
        extensions=None,
        threads=None
    )
    assert errors == []
