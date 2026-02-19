"""Branch-path tests for r2inspect/cli/validators.py."""
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
# validate_inputs – integration (lines 59-69)
# ---------------------------------------------------------------------------


def test_validate_inputs_all_none_produces_no_errors():
    """Lines 59-69: validate_inputs with all None inputs returns empty list."""
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


def test_validate_inputs_accumulates_errors_from_all_validators(tmp_path):
    """Lines 61-67: each sub-validator is called and errors are collected."""
    errors = validate_inputs(
        filename=str(tmp_path / "no_file.bin"),
        batch=str(tmp_path / "no_dir"),
        output=None,
        yara=str(tmp_path / "no_yara_dir"),
        config=str(tmp_path / "no_config.json"),
        extensions="@bad!",
        threads=999,
    )
    assert len(errors) >= 5


def test_validate_inputs_valid_file_no_errors(tmp_path):
    """Lines 61-69: valid file input produces no file-related errors."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 100)
    errors = validate_inputs(
        filename=str(sample),
        batch=None,
        output=None,
        yara=None,
        config=None,
        extensions=None,
        threads=None,
    )
    assert errors == []


def test_validate_inputs_valid_batch_no_errors(tmp_path):
    """Lines 62-69: valid batch directory produces no batch errors."""
    errors = validate_inputs(
        filename=None,
        batch=str(tmp_path),
        output=None,
        yara=None,
        config=None,
        extensions=None,
        threads=None,
    )
    assert errors == []


def test_validate_inputs_threads_error_is_collected():
    """Line 67: threads validator error is included in results."""
    errors = validate_inputs(
        filename=None,
        batch=None,
        output=None,
        yara=None,
        config=None,
        extensions=None,
        threads=100,
    )
    assert any("threads" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# validate_file_input (lines 88-116)
# ---------------------------------------------------------------------------


def test_validate_file_input_none_returns_no_errors():
    """Line 88-89: None input returns empty list without entering if block."""
    assert validate_file_input(None) == []


def test_validate_file_input_valid_small_file(tmp_path):
    """Lines 88-116: valid file with nonzero size returns no errors."""
    f = tmp_path / "valid.bin"
    f.write_bytes(b"\x7fELF" + b"\x00" * 100)
    assert validate_file_input(str(f)) == []


def test_validate_file_input_empty_file_reports_error(tmp_path):
    """Lines 103-105: empty file reports 'empty' error."""
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    errors = validate_file_input(str(f))
    assert len(errors) == 1
    assert "empty" in errors[0].lower()


def test_validate_file_input_directory_not_regular_file(tmp_path):
    """Lines 99-100: directory path reports 'not a regular file' error."""
    errors = validate_file_input(str(tmp_path))
    assert len(errors) == 1
    assert "not a regular file" in errors[0].lower()


def test_validate_file_input_missing_file_reports_error(tmp_path):
    """Lines 109-114: nonexistent file triggers OSError/security error."""
    errors = validate_file_input(str(tmp_path / "no_such_file.bin"))
    assert len(errors) >= 1


def test_validate_file_input_security_violation_path():
    """Lines 109-111: path with dangerous chars triggers ValueError from FileValidator."""
    # Semicolon is a dangerous character per FileValidator.DANGEROUS_CHARS
    errors = validate_file_input("/tmp/evil;rm -rf /")
    assert len(errors) == 1
    assert "security validation failed" in errors[0].lower()


def test_validate_file_input_null_byte_triggers_security_error():
    """Lines 109-111: path with null byte triggers ValueError."""
    errors = validate_file_input("/tmp/file\x00name")
    assert len(errors) == 1
    assert "security validation failed" in errors[0].lower()


def test_validate_file_input_simulated_os_error(tmp_path):
    """Lines 112-114: simulated OSError is reported."""
    f = tmp_path / "sample.bin"
    f.write_bytes(b"x" * 100)
    os.environ["R2INSPECT_TEST_RAISE_FILE_ERROR"] = "1"
    try:
        errors = validate_file_input(str(f))
        assert len(errors) == 1
        assert "access error" in errors[0].lower()
    finally:
        del os.environ["R2INSPECT_TEST_RAISE_FILE_ERROR"]


# ---------------------------------------------------------------------------
# validate_batch_input (lines 131-148)
# ---------------------------------------------------------------------------


def test_validate_batch_input_none_returns_no_errors():
    """Line 131-132: None input is skipped."""
    assert validate_batch_input(None) == []


def test_validate_batch_input_valid_directory(tmp_path):
    """Lines 133-141: valid directory produces no errors."""
    assert validate_batch_input(str(tmp_path)) == []


def test_validate_batch_input_file_not_directory(tmp_path):
    """Lines 138-139: file path reports 'not a directory' error."""
    f = tmp_path / "file.txt"
    f.write_text("data")
    errors = validate_batch_input(str(f))
    assert len(errors) == 1
    assert "not a directory" in errors[0].lower()


def test_validate_batch_input_nonexistent_triggers_error(tmp_path):
    """Lines 143-146: nonexistent path triggers error."""
    errors = validate_batch_input(str(tmp_path / "no_such_dir"))
    assert len(errors) >= 1


def test_validate_batch_input_security_violation():
    """Lines 143-144: path with dangerous chars triggers security ValueError."""
    errors = validate_batch_input("/tmp/batch$dir")
    assert len(errors) == 1
    assert "security validation failed" in errors[0].lower()


def test_validate_batch_input_simulated_os_error(tmp_path):
    """Lines 145-146: simulated OSError is reported."""
    os.environ["R2INSPECT_TEST_RAISE_BATCH_ERROR"] = "1"
    try:
        errors = validate_batch_input(str(tmp_path))
        assert len(errors) == 1
        assert "access error" in errors[0].lower()
    finally:
        del os.environ["R2INSPECT_TEST_RAISE_BATCH_ERROR"]


# ---------------------------------------------------------------------------
# validate_output_input (lines 161-176)
# ---------------------------------------------------------------------------


def test_validate_output_input_none_returns_no_errors():
    """Line 161: None input returns empty list."""
    assert validate_output_input(None) == []


def test_validate_output_input_writable_existing_file(tmp_path):
    """Lines 164-169: writable existing file passes."""
    f = tmp_path / "out.json"
    f.write_text("{}")
    assert validate_output_input(str(f)) == []


def test_validate_output_input_nonexistent_with_extension(tmp_path):
    """Lines 162-163: nonexistent path with extension has no parent-dir check."""
    path = tmp_path / "out.json"
    assert validate_output_input(str(path)) == []


def test_validate_output_input_parent_file_not_directory(tmp_path):
    """Lines 172-175: no-extension path whose parent is a file reports error."""
    parent_file = tmp_path / "notadir.txt"
    parent_file.write_text("data")
    nested = parent_file / "subpath"
    errors = validate_output_input(str(nested))
    assert len(errors) == 1
    assert "not a directory" in errors[0].lower()


def test_validate_output_input_nonexistent_no_extension_valid_parent(tmp_path):
    """Lines 172-175: no-extension path with valid parent directory returns no errors."""
    path = tmp_path / "outdir"
    assert validate_output_input(str(path)) == []


def test_validate_output_input_read_only_file_reports_error(tmp_path):
    """Lines 170-171: read-only existing file reports cannot-write error."""
    f = tmp_path / "readonly.json"
    f.write_text("{}")
    f.chmod(0o444)
    try:
        errors = validate_output_input(str(f))
        if sys.platform != "win32":
            assert len(errors) == 1
            assert "cannot write" in errors[0].lower()
    finally:
        f.chmod(0o644)


# ---------------------------------------------------------------------------
# validate_yara_input (lines 189-196)
# ---------------------------------------------------------------------------


def test_validate_yara_input_none_returns_no_errors():
    assert validate_yara_input(None) == []


def test_validate_yara_input_valid_directory(tmp_path):
    """Lines 189-195: valid directory returns no errors."""
    d = tmp_path / "rules"
    d.mkdir()
    assert validate_yara_input(str(d)) == []


def test_validate_yara_input_missing_path(tmp_path):
    """Lines 192-193: missing path reports does-not-exist error."""
    errors = validate_yara_input(str(tmp_path / "missing"))
    assert len(errors) == 1
    assert "does not exist" in errors[0].lower()


def test_validate_yara_input_file_not_directory(tmp_path):
    """Lines 194-195: file path reports 'not a directory' error."""
    f = tmp_path / "rules.yar"
    f.write_text("rule x {}")
    errors = validate_yara_input(str(f))
    assert len(errors) == 1
    assert "not a directory" in errors[0].lower()


# ---------------------------------------------------------------------------
# validate_config_input (lines 209-218)
# ---------------------------------------------------------------------------


def test_validate_config_input_none_returns_no_errors():
    assert validate_config_input(None) == []


def test_validate_config_input_valid_json_file(tmp_path):
    """Lines 209-218: valid .json file returns no errors."""
    f = tmp_path / "cfg.json"
    f.write_text("{}")
    assert validate_config_input(str(f)) == []


def test_validate_config_input_valid_yaml_file(tmp_path):
    """Lines 209-218: valid .yaml file returns no errors."""
    f = tmp_path / "cfg.yaml"
    f.write_text("key: val")
    assert validate_config_input(str(f)) == []


def test_validate_config_input_valid_yml_file(tmp_path):
    f = tmp_path / "cfg.yml"
    f.write_text("key: val")
    assert validate_config_input(str(f)) == []


def test_validate_config_input_valid_toml_file(tmp_path):
    f = tmp_path / "cfg.toml"
    f.write_text("[s]\nk=1")
    assert validate_config_input(str(f)) == []


def test_validate_config_input_missing_file(tmp_path):
    """Lines 212-213: missing file reports 'does not exist'."""
    errors = validate_config_input(str(tmp_path / "no_cfg.json"))
    assert any("does not exist" in e.lower() for e in errors)


def test_validate_config_input_directory_not_file(tmp_path):
    """Lines 214-215: directory path reports 'not a file'."""
    errors = validate_config_input(str(tmp_path))
    assert any("not a file" in e.lower() for e in errors)


def test_validate_config_input_unsupported_extension(tmp_path):
    """Lines 216-217: unsupported extension reports format error."""
    f = tmp_path / "cfg.ini"
    f.write_text("[s]\nk=v")
    errors = validate_config_input(str(f))
    assert any("json" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# validate_extensions_input (lines 231-239)
# ---------------------------------------------------------------------------


def test_validate_extensions_input_none_returns_no_errors():
    assert validate_extensions_input(None) == []


def test_validate_extensions_input_single_valid_extension():
    assert validate_extensions_input("exe") == []


def test_validate_extensions_input_multiple_valid_extensions():
    assert validate_extensions_input("exe,dll,sys") == []


def test_validate_extensions_input_extension_with_dot():
    assert validate_extensions_input(".exe") == []


def test_validate_extensions_input_extension_with_hyphen_and_underscore():
    assert validate_extensions_input("my-ext,my_ext") == []


def test_validate_extensions_input_invalid_special_chars():
    """Lines 235-236: special chars produce invalid-extension error."""
    errors = validate_extensions_input("exe@bad")
    assert any("invalid file extension" in e.lower() for e in errors)


def test_validate_extensions_input_too_long_extension():
    """Lines 237-238: extension >10 chars produces too-long error."""
    errors = validate_extensions_input("a" * 11)
    assert any("too long" in e.lower() for e in errors)


def test_validate_extensions_input_multiple_errors_for_multiple_bad_exts():
    errors = validate_extensions_input("@bad1,#bad2")
    assert len(errors) >= 2


# ---------------------------------------------------------------------------
# validate_threads_input (lines 252-258)
# ---------------------------------------------------------------------------


def test_validate_threads_input_none_returns_no_errors():
    assert validate_threads_input(None) == []


def test_validate_threads_input_valid_positive_integer():
    assert validate_threads_input(4) == []


def test_validate_threads_input_minimum_one():
    assert validate_threads_input(1) == []


def test_validate_threads_input_maximum_fifty():
    assert validate_threads_input(50) == []


def test_validate_threads_input_zero_is_invalid():
    """Lines 254-255: zero is not a positive integer."""
    errors = validate_threads_input(0)
    assert any("positive integer" in e.lower() for e in errors)


def test_validate_threads_input_negative_is_invalid():
    """Lines 254-255: negative value is invalid."""
    errors = validate_threads_input(-5)
    assert any("positive integer" in e.lower() for e in errors)


def test_validate_threads_input_above_fifty_is_invalid():
    """Lines 256-257: value above 50 is invalid."""
    errors = validate_threads_input(51)
    assert any("too many threads" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# display_validation_errors (lines 268-269)
# ---------------------------------------------------------------------------


def test_display_validation_errors_prints_each_error(capsys):
    """Lines 268-269: each error is printed."""
    display_validation_errors(["Error A", "Error B"])
    out = capsys.readouterr().out
    assert "Error A" in out
    assert "Error B" in out


def test_display_validation_errors_empty_list_prints_nothing(capsys):
    display_validation_errors([])
    assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# validate_input_mode (lines 282-291)
# ---------------------------------------------------------------------------


def test_validate_input_mode_no_args_exits():
    """Lines 282-284: neither filename nor batch -> sys.exit(1)."""
    with pytest.raises(SystemExit) as exc_info:
        validate_input_mode(None, None)
    assert exc_info.value.code == 1


def test_validate_input_mode_both_args_exits(tmp_path):
    """Lines 286-288: both filename and batch -> sys.exit(1)."""
    f = tmp_path / "f.bin"
    f.write_bytes(b"data")
    with pytest.raises(SystemExit) as exc_info:
        validate_input_mode(str(f), str(tmp_path))
    assert exc_info.value.code == 1


def test_validate_input_mode_batch_only_passes(tmp_path):
    """Lines 290-291: batch only -> no exit."""
    validate_input_mode(None, str(tmp_path))


def test_validate_input_mode_filename_valid_file(tmp_path):
    """Lines 290-291: valid filename only -> no exit."""
    f = tmp_path / "sample.bin"
    f.write_bytes(b"data")
    validate_input_mode(str(f), None)


# ---------------------------------------------------------------------------
# validate_single_file (lines 303-312)
# ---------------------------------------------------------------------------


def test_validate_single_file_valid_file_does_not_exit(tmp_path):
    """Lines 303-312: valid file passes without SystemExit."""
    f = tmp_path / "sample.bin"
    f.write_bytes(b"data")
    validate_single_file(str(f))


def test_validate_single_file_missing_file_exits():
    """Lines 304-309: missing file -> sys.exit(1)."""
    with pytest.raises(SystemExit) as exc_info:
        validate_single_file("/tmp/this_file_does_not_exist_12345.bin")
    assert exc_info.value.code == 1


def test_validate_single_file_directory_exits(tmp_path):
    """Lines 310-312: directory path -> sys.exit(1)."""
    with pytest.raises(SystemExit) as exc_info:
        validate_single_file(str(tmp_path))
    assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# sanitize_xor_string (lines 325-336)
# ---------------------------------------------------------------------------


def test_sanitize_xor_string_none_returns_none():
    assert sanitize_xor_string(None) is None


def test_sanitize_xor_string_empty_returns_none():
    assert sanitize_xor_string("") is None


def test_sanitize_xor_string_valid_alphanum():
    assert sanitize_xor_string("hello123") == "hello123"


def test_sanitize_xor_string_preserves_allowed_special_chars():
    result = sanitize_xor_string("key_val-1.0 ")
    assert result == "key_val-1.0 "


def test_sanitize_xor_string_removes_dangerous_chars():
    """Lines 329-330: dangerous characters are filtered out."""
    result = sanitize_xor_string("key@#!")
    assert result == "key"


def test_sanitize_xor_string_all_invalid_returns_none():
    result = sanitize_xor_string("@#$%^")
    assert result is None


def test_sanitize_xor_string_truncates_to_100():
    """Lines 333-334: strings longer than 100 chars are truncated."""
    result = sanitize_xor_string("a" * 200)
    assert len(result) == 100


# ---------------------------------------------------------------------------
# handle_xor_input (lines 349-354)
# ---------------------------------------------------------------------------


def test_handle_xor_input_none_returns_none():
    assert handle_xor_input(None) is None


def test_handle_xor_input_valid_returns_sanitized():
    assert handle_xor_input("mykey") == "mykey"


def test_handle_xor_input_all_invalid_prints_warning(capsys):
    """Lines 350-353: warning is printed when sanitized result is None."""
    result = handle_xor_input("@@@")
    assert result is None
    out = capsys.readouterr().out
    assert "warning" in out.lower() or "invalid" in out.lower()
