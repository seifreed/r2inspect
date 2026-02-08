from __future__ import annotations

import sys
from pathlib import Path

import pytest

from r2inspect.cli import validators


def test_validate_file_input(tmp_path: Path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    errors = validators.validate_file_input(str(empty))
    assert any("File is empty" in e for e in errors)

    bad = "bad;name"
    errors = validators.validate_file_input(bad)
    assert any("security validation failed" in e for e in errors)


def test_validate_batch_output_and_config(tmp_path: Path):
    file_path = tmp_path / "file.bin"
    file_path.write_text("x")

    errors = validators.validate_batch_input(str(file_path))
    assert any("not a directory" in e for e in errors)

    output_file = tmp_path / "out.txt"
    output_file.write_text("x")
    output_file.chmod(0o400)
    try:
        errors = validators.validate_output_input(str(output_file))
        assert any("Cannot write" in e for e in errors)
    finally:
        output_file.chmod(0o600)

    config_file = tmp_path / "config.bad"
    config_file.write_text("x")
    errors = validators.validate_config_input(str(config_file))
    assert any("Config file must be" in e for e in errors)


def test_validate_yara_extensions_threads(tmp_path: Path):
    yara_dir = tmp_path / "yara"
    errors = validators.validate_yara_input(str(yara_dir))
    assert any("does not exist" in e for e in errors)

    errors = validators.validate_extensions_input(".ok, bad$ext, toolongextension")
    assert any("Invalid file extension" in e for e in errors)
    assert any("File extension too long" in e for e in errors)

    errors = validators.validate_threads_input(0)
    assert errors == ["Threads must be a positive integer"]

    errors = validators.validate_threads_input(100)
    assert errors == ["Too many threads (max 50)"]


def test_validate_input_mode_and_single_file(tmp_path: Path, capsys):
    with pytest.raises(SystemExit):
        validators.validate_input_mode(None, None)
    with pytest.raises(SystemExit):
        validators.validate_input_mode("a", "b")

    missing = tmp_path / "missing.bin"
    with pytest.raises(SystemExit):
        validators.validate_single_file(str(missing))
    captured = capsys.readouterr()
    assert "does not exist" in captured.out


def test_sanitize_xor_and_handle_xor():
    assert validators.sanitize_xor_string(None) is None
    assert validators.sanitize_xor_string("@@@") is None

    long = "a" * 200
    sanitized = validators.sanitize_xor_string(long)
    assert len(sanitized) == 100

    result = validators.handle_xor_input("bad@@")
    assert result == "bad"
