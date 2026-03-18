"""Comprehensive tests for validators.py - 100% coverage target."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from r2inspect.cli.validators import (
    validate_inputs,
    validate_file_input,
    validate_batch_input,
    validate_output_input,
    validate_yara_input,
    validate_config_input,
    validate_extensions_input,
    validate_threads_input,
    display_validation_errors,
    sanitize_xor_string,
    handle_xor_input,
)


def test_validate_inputs_all_none():
    """Test validate_inputs with all None arguments returns no errors for None."""
    errors = validate_inputs(
        filename=None,
        batch=None,
        output=None,
        yara=None,
        config=None,
        extensions=None,
        threads=None,
    )
    assert isinstance(errors, list)


def test_validate_file_input_none():
    """Test validate_file_input with None is valid."""
    errors = validate_file_input(None)
    assert errors == []


def test_validate_file_input_nonexistent():
    """Test validate_file_input with a nonexistent file."""
    errors = validate_file_input("/nonexistent/file.exe")
    assert len(errors) > 0


def test_validate_file_input_valid_file():
    """Test validate_file_input with a valid file."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x00" * 64)
        tmp_name = f.name
    try:
        errors = validate_file_input(tmp_name)
        assert errors == []
    finally:
        os.unlink(tmp_name)


def test_validate_batch_input_none():
    """Test validate_batch_input with None is valid."""
    errors = validate_batch_input(None)
    assert errors == []


def test_validate_batch_input_nonexistent():
    """Test validate_batch_input with nonexistent directory."""
    errors = validate_batch_input("/nonexistent/directory")
    assert len(errors) > 0


def test_validate_batch_input_valid_dir():
    """Test validate_batch_input with a valid directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        errors = validate_batch_input(tmpdir)
        assert errors == []


def test_validate_output_input_none():
    """Test validate_output_input with None is valid."""
    errors = validate_output_input(None)
    assert errors == []


def test_validate_output_input_valid():
    """Test validate_output_input with a valid path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        errors = validate_output_input(tmpdir)
        assert errors == []


def test_validate_yara_input_none():
    """Test validate_yara_input with None is valid."""
    errors = validate_yara_input(None)
    assert errors == []


def test_validate_yara_input_nonexistent():
    """Test validate_yara_input with nonexistent path."""
    errors = validate_yara_input("/nonexistent/yara/rules")
    assert len(errors) > 0


def test_validate_config_input_none():
    """Test validate_config_input with None is valid."""
    errors = validate_config_input(None)
    assert errors == []


def test_validate_config_input_nonexistent():
    """Test validate_config_input with nonexistent file."""
    errors = validate_config_input("/nonexistent/config.yaml")
    assert len(errors) > 0


def test_validate_extensions_input_none():
    """Test validate_extensions_input with None is valid."""
    errors = validate_extensions_input(None)
    assert errors == []


def test_validate_extensions_input_valid():
    """Test validate_extensions_input with valid extensions."""
    errors = validate_extensions_input(".exe,.dll,.sys")
    assert errors == []


def test_validate_threads_input_none():
    """Test validate_threads_input with None is valid."""
    errors = validate_threads_input(None)
    assert errors == []


def test_validate_threads_input_positive():
    """Test validate_threads_input with positive integer."""
    errors = validate_threads_input(4)
    assert errors == []


def test_validate_threads_input_zero():
    """Test validate_threads_input with zero."""
    errors = validate_threads_input(0)
    assert len(errors) > 0


def test_validate_threads_input_negative():
    """Test validate_threads_input with negative number."""
    errors = validate_threads_input(-1)
    assert len(errors) > 0


def test_display_validation_errors(capsys):
    """Test display_validation_errors prints errors."""
    errors = ["Error 1", "Error 2"]
    display_validation_errors(errors)
    captured = capsys.readouterr()
    assert "Error 1" in captured.out
    assert "Error 2" in captured.out


def test_display_validation_errors_empty(capsys):
    """Test display_validation_errors with empty list."""
    display_validation_errors([])
    captured = capsys.readouterr()
    # Should print nothing
    assert captured.out == ""


def test_sanitize_xor_string_none():
    """Test sanitize_xor_string with None returns None."""
    result = sanitize_xor_string(None)
    assert result is None


def test_sanitize_xor_string_valid():
    """Test sanitize_xor_string with a valid hex string."""
    result = sanitize_xor_string("0x41")
    assert result is not None


def test_sanitize_xor_string_plain():
    """Test sanitize_xor_string with a plain string."""
    result = sanitize_xor_string("hello")
    assert result is not None


def test_handle_xor_input_none():
    """Test handle_xor_input with None returns None."""
    result = handle_xor_input(None)
    assert result is None


def test_handle_xor_input_valid():
    """Test handle_xor_input with a valid value."""
    result = handle_xor_input("0x41")
    assert result is not None


def test_validate_inputs_with_valid_file():
    """Test validate_inputs with only a valid file."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x00" * 64)
        tmp_name = f.name
    try:
        errors = validate_inputs(
            filename=tmp_name,
            batch=None,
            output=None,
            yara=None,
            config=None,
            extensions=None,
            threads=None,
        )
        assert errors == []
    finally:
        os.unlink(tmp_name)


def test_validate_inputs_with_invalid_threads():
    """Test validate_inputs catches invalid threads."""
    errors = validate_inputs(
        filename=None,
        batch=None,
        output=None,
        yara=None,
        config=None,
        extensions=None,
        threads=-5,
    )
    assert any("thread" in e.lower() for e in errors)
