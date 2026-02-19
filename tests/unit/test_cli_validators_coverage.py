"""
Tests for r2inspect/cli/validators.py - coverage without mocks.

Covers all validation functions with real file system operations,
environment variable manipulation, and direct code path testing.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

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


# ---------------------------------------------------------------------------
# validate_file_input
# ---------------------------------------------------------------------------


def test_validate_file_input_none_returns_no_errors():
    errors = validate_file_input(None)
    assert errors == []


def test_validate_file_input_valid_file(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 200)
    errors = validate_file_input(str(sample))
    assert errors == []


def test_validate_file_input_empty_file(tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    errors = validate_file_input(str(empty))
    assert len(errors) == 1
    assert "empty" in errors[0].lower()


def test_validate_file_input_missing_file(tmp_path):
    errors = validate_file_input(str(tmp_path / "no_such_file.bin"))
    assert len(errors) > 0


def test_validate_file_input_directory_is_not_a_file(tmp_path):
    errors = validate_file_input(str(tmp_path))
    assert len(errors) == 1
    assert "not a regular file" in errors[0].lower()


def test_validate_file_input_simulated_os_error(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 100)
    os.environ["R2INSPECT_TEST_RAISE_FILE_ERROR"] = "1"
    try:
        errors = validate_file_input(str(sample))
        assert len(errors) > 0
        assert "access error" in errors[0].lower()
    finally:
        del os.environ["R2INSPECT_TEST_RAISE_FILE_ERROR"]


# ---------------------------------------------------------------------------
# validate_batch_input
# ---------------------------------------------------------------------------


def test_validate_batch_input_none_returns_no_errors():
    errors = validate_batch_input(None)
    assert errors == []


def test_validate_batch_input_valid_directory(tmp_path):
    errors = validate_batch_input(str(tmp_path))
    assert errors == []


def test_validate_batch_input_file_is_not_a_directory(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("data")
    errors = validate_batch_input(str(f))
    assert len(errors) == 1
    assert "not a directory" in errors[0].lower()


def test_validate_batch_input_missing_path(tmp_path):
    errors = validate_batch_input(str(tmp_path / "no_such_dir"))
    assert len(errors) > 0


def test_validate_batch_input_simulated_os_error(tmp_path):
    os.environ["R2INSPECT_TEST_RAISE_BATCH_ERROR"] = "1"
    try:
        errors = validate_batch_input(str(tmp_path))
        assert len(errors) > 0
        assert "access error" in errors[0].lower()
    finally:
        del os.environ["R2INSPECT_TEST_RAISE_BATCH_ERROR"]


# ---------------------------------------------------------------------------
# validate_output_input
# ---------------------------------------------------------------------------


def test_validate_output_input_none_returns_no_errors():
    errors = validate_output_input(None)
    assert errors == []


def test_validate_output_input_writable_existing_file(tmp_path):
    f = tmp_path / "out.json"
    f.write_text("{}")
    errors = validate_output_input(str(f))
    assert errors == []


def test_validate_output_input_read_only_file(tmp_path):
    f = tmp_path / "readonly.json"
    f.write_text("{}")
    f.chmod(0o444)
    errors = validate_output_input(str(f))
    if sys.platform != "win32":
        assert len(errors) == 1
        assert "cannot write" in errors[0].lower()
    f.chmod(0o644)


def test_validate_output_input_nonexistent_path_no_extension(tmp_path):
    # Path has no extension - parent exists and is a dir, no error expected
    output_dir = tmp_path / "newoutdir"
    errors = validate_output_input(str(output_dir))
    assert errors == []


def test_validate_output_input_parent_not_a_directory(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("data")
    # Parent "file.txt" is a file, not a directory
    nested = f / "subpath"
    errors = validate_output_input(str(nested))
    assert len(errors) == 1
    assert "not a directory" in errors[0].lower()


# ---------------------------------------------------------------------------
# validate_yara_input
# ---------------------------------------------------------------------------


def test_validate_yara_input_none_returns_no_errors():
    errors = validate_yara_input(None)
    assert errors == []


def test_validate_yara_input_valid_directory(tmp_path):
    yara_dir = tmp_path / "rules"
    yara_dir.mkdir()
    errors = validate_yara_input(str(yara_dir))
    assert errors == []


def test_validate_yara_input_missing_path(tmp_path):
    errors = validate_yara_input(str(tmp_path / "no_such_yara"))
    assert len(errors) == 1
    assert "does not exist" in errors[0].lower()


def test_validate_yara_input_file_is_not_a_directory(tmp_path):
    yara_file = tmp_path / "rules.yar"
    yara_file.write_text("rule test {}")
    errors = validate_yara_input(str(yara_file))
    assert len(errors) == 1
    assert "not a directory" in errors[0].lower()


# ---------------------------------------------------------------------------
# validate_config_input
# ---------------------------------------------------------------------------


def test_validate_config_input_none_returns_no_errors():
    errors = validate_config_input(None)
    assert errors == []


def test_validate_config_input_valid_json(tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text("{}")
    errors = validate_config_input(str(cfg))
    assert errors == []


def test_validate_config_input_valid_yaml(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("key: value")
    errors = validate_config_input(str(cfg))
    assert errors == []


def test_validate_config_input_valid_yml(tmp_path):
    cfg = tmp_path / "config.yml"
    cfg.write_text("key: value")
    errors = validate_config_input(str(cfg))
    assert errors == []


def test_validate_config_input_valid_toml(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[section]\nkey = "val"')
    errors = validate_config_input(str(cfg))
    assert errors == []


def test_validate_config_input_missing_file(tmp_path):
    errors = validate_config_input(str(tmp_path / "no_config.json"))
    assert len(errors) == 1
    assert "does not exist" in errors[0].lower()


def test_validate_config_input_directory_is_not_a_file(tmp_path):
    errors = validate_config_input(str(tmp_path))
    assert len(errors) == 1
    assert "not a file" in errors[0].lower()


def test_validate_config_input_invalid_extension(tmp_path):
    cfg = tmp_path / "config.ini"
    cfg.write_text("[section]\nkey=value")
    errors = validate_config_input(str(cfg))
    assert len(errors) == 1
    assert "json" in errors[0].lower()


# ---------------------------------------------------------------------------
# validate_extensions_input
# ---------------------------------------------------------------------------


def test_validate_extensions_input_none_returns_no_errors():
    errors = validate_extensions_input(None)
    assert errors == []


def test_validate_extensions_input_single_valid():
    errors = validate_extensions_input("exe")
    assert errors == []


def test_validate_extensions_input_multiple_valid():
    errors = validate_extensions_input("exe,dll,sys")
    assert errors == []


def test_validate_extensions_input_with_dots_and_spaces():
    errors = validate_extensions_input(".exe, .dll")
    assert errors == []


def test_validate_extensions_input_with_underscores_and_hyphens():
    errors = validate_extensions_input("my_ext,my-ext")
    assert errors == []


def test_validate_extensions_input_invalid_characters():
    errors = validate_extensions_input("exe@, dll#")
    assert len(errors) >= 2
    assert all("invalid file extension" in e.lower() for e in errors)


def test_validate_extensions_input_too_long():
    errors = validate_extensions_input("a" * 11)
    assert len(errors) == 1
    assert "too long" in errors[0].lower()


# ---------------------------------------------------------------------------
# validate_threads_input
# ---------------------------------------------------------------------------


def test_validate_threads_input_none_returns_no_errors():
    errors = validate_threads_input(None)
    assert errors == []


def test_validate_threads_input_valid_value():
    errors = validate_threads_input(10)
    assert errors == []


def test_validate_threads_input_minimum_valid():
    errors = validate_threads_input(1)
    assert errors == []


def test_validate_threads_input_maximum_valid():
    errors = validate_threads_input(50)
    assert errors == []


def test_validate_threads_input_zero_is_invalid():
    errors = validate_threads_input(0)
    assert len(errors) == 1
    assert "positive integer" in errors[0].lower()


def test_validate_threads_input_negative_is_invalid():
    errors = validate_threads_input(-1)
    assert len(errors) == 1
    assert "positive integer" in errors[0].lower()


def test_validate_threads_input_above_maximum_is_invalid():
    errors = validate_threads_input(51)
    assert len(errors) == 1
    assert "too many threads" in errors[0].lower()


# ---------------------------------------------------------------------------
# sanitize_xor_string
# ---------------------------------------------------------------------------


def test_sanitize_xor_string_none_returns_none():
    assert sanitize_xor_string(None) is None


def test_sanitize_xor_string_empty_returns_none():
    assert sanitize_xor_string("") is None


def test_sanitize_xor_string_valid_alphanumeric():
    assert sanitize_xor_string("hello123") == "hello123"


def test_sanitize_xor_string_preserves_allowed_symbols():
    result = sanitize_xor_string("abc_XY-12.Z ")
    assert result == "abc_XY-12.Z "


def test_sanitize_xor_string_strips_invalid_characters():
    result = sanitize_xor_string("test@#$%")
    assert result == "test"


def test_sanitize_xor_string_all_invalid_returns_none():
    result = sanitize_xor_string("@#$%^&*()")
    assert result is None


def test_sanitize_xor_string_truncates_to_100_chars():
    result = sanitize_xor_string("a" * 150)
    assert len(result) == 100


# ---------------------------------------------------------------------------
# handle_xor_input
# ---------------------------------------------------------------------------


def test_handle_xor_input_none_returns_none():
    assert handle_xor_input(None) is None


def test_handle_xor_input_valid_string_passes_through():
    result = handle_xor_input("mykey123")
    assert result == "mykey123"


def test_handle_xor_input_all_invalid_chars_triggers_warning(capsys):
    # xor is non-empty but all chars are invalid, so sanitized is None
    result = handle_xor_input("@#$%^&*()")
    assert result is None
    captured = capsys.readouterr()
    assert "warning" in captured.out.lower() or "invalid" in captured.out.lower()


# ---------------------------------------------------------------------------
# display_validation_errors
# ---------------------------------------------------------------------------


def test_display_validation_errors_prints_all_messages(capsys):
    display_validation_errors(["Error A", "Error B"])
    out = capsys.readouterr().out
    assert "Error A" in out
    assert "Error B" in out


def test_display_validation_errors_empty_list_prints_nothing(capsys):
    display_validation_errors([])
    out = capsys.readouterr().out
    assert out == ""


# ---------------------------------------------------------------------------
# validate_input_mode
# ---------------------------------------------------------------------------


def test_validate_input_mode_both_provided_exits(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"data")
    with pytest.raises(SystemExit) as exc_info:
        validate_input_mode(str(f), str(tmp_path))
    assert exc_info.value.code == 1


def test_validate_input_mode_neither_provided_exits():
    with pytest.raises(SystemExit) as exc_info:
        validate_input_mode(None, None)
    assert exc_info.value.code == 1


def test_validate_input_mode_batch_only_succeeds(tmp_path):
    validate_input_mode(None, str(tmp_path))


def test_validate_input_mode_filename_only_valid(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"data")
    validate_input_mode(str(f), None)


# ---------------------------------------------------------------------------
# validate_single_file
# ---------------------------------------------------------------------------


def test_validate_single_file_valid(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"data")
    validate_single_file(str(f))  # should not raise


def test_validate_single_file_missing_exits(tmp_path):
    with pytest.raises(SystemExit) as exc_info:
        validate_single_file(str(tmp_path / "missing.bin"))
    assert exc_info.value.code == 1


def test_validate_single_file_directory_exits(tmp_path):
    with pytest.raises(SystemExit) as exc_info:
        validate_single_file(str(tmp_path))
    assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# validate_inputs (integration)
# ---------------------------------------------------------------------------


def test_validate_inputs_all_none_returns_no_errors():
    errors = validate_inputs(
        filename=None,
        batch=None,
        output=None,
        yara=None,
        config=None,
        extensions=None,
        threads=None,
    )
    assert errors == []


def test_validate_inputs_collects_multiple_errors(tmp_path):
    errors = validate_inputs(
        filename=str(tmp_path / "missing.bin"),
        batch=str(tmp_path / "missing_dir"),
        output=None,
        yara=str(tmp_path / "missing_yara"),
        config=str(tmp_path / "missing.json"),
        extensions="@invalid",
        threads=999,
    )
    assert len(errors) >= 4


def test_validate_inputs_valid_inputs(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 200)
    yara_dir = tmp_path / "yara"
    yara_dir.mkdir()
    cfg = tmp_path / "config.json"
    cfg.write_text("{}")

    errors = validate_inputs(
        filename=str(sample),
        batch=None,
        output=None,
        yara=str(yara_dir),
        config=str(cfg),
        extensions="exe,dll",
        threads=4,
    )
    assert errors == []
