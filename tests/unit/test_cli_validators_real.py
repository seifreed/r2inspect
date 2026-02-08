from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from r2inspect.cli import validators


def _make_sparse_file(path: Path, size_bytes: int) -> None:
    with open(path, "wb") as handle:
        handle.seek(size_bytes - 1)
        handle.write(b"\0")


def test_validate_file_input_variants(tmp_path: Path) -> None:
    valid_file = tmp_path / "sample.bin"
    valid_file.write_bytes(b"data")
    assert validators.validate_file_input(str(valid_file)) == []

    empty_file = tmp_path / "empty.bin"
    empty_file.touch()
    errors = validators.validate_file_input(str(empty_file))
    assert any("File is empty" in error for error in errors)

    errors = validators.validate_file_input(str(tmp_path))
    assert any("Path is not a regular file" in error for error in errors)

    large_file = tmp_path / "large.bin"
    _make_sparse_file(large_file, 1024 * 1024 * 1024 + 1)
    errors = validators.validate_file_input(str(large_file))
    assert any("File too large" in error for error in errors)

    errors = validators.validate_file_input("bad;name")
    assert any("File path security validation failed" in error for error in errors)


def test_validate_batch_output_config_yara_inputs(tmp_path: Path) -> None:
    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()
    batch_file = tmp_path / "batch.txt"
    batch_file.write_text("x", encoding="utf-8")

    assert validators.validate_batch_input(str(batch_dir)) == []
    errors = validators.validate_batch_input(str(batch_file))
    assert any("Batch path is not a directory" in error for error in errors)

    output_file = tmp_path / "out.csv"
    output_file.write_text("x", encoding="utf-8")
    output_file.chmod(0o400)
    errors = validators.validate_output_input(str(output_file))
    assert any("Cannot write to output file" in error for error in errors)

    parent_file = tmp_path / "parent"
    parent_file.write_text("x", encoding="utf-8")
    output_path = parent_file / "child"
    errors = validators.validate_output_input(str(output_path))
    assert any("Output parent path is not a directory" in error for error in errors)

    missing_yara = tmp_path / "missing_yara"
    errors = validators.validate_yara_input(str(missing_yara))
    assert any("YARA rules directory does not exist" in error for error in errors)

    errors = validators.validate_yara_input(str(batch_file))
    assert any("YARA path is not a directory" in error for error in errors)

    config_dir = tmp_path / "cfgdir"
    config_dir.mkdir()
    errors = validators.validate_config_input(str(config_dir))
    assert any("Config path is not a file" in error for error in errors)

    bad_config = tmp_path / "config.bad"
    bad_config.write_text("x", encoding="utf-8")
    errors = validators.validate_config_input(str(bad_config))
    assert any("Config file must be JSON" in error for error in errors)


def test_validate_extensions_threads_and_modes(tmp_path: Path) -> None:
    valid_file = tmp_path / "valid.bin"
    valid_file.write_text("x", encoding="utf-8")
    valid_batch = tmp_path / "batch"
    valid_batch.mkdir()
    output_path = tmp_path / "out.json"

    errors = validators.validate_inputs(
        filename=str(valid_file),
        batch=None,
        output=str(output_path),
        yara=None,
        config=None,
        extensions="exe",
        threads=1,
    )
    assert errors == []

    errors = validators.validate_extensions_input("b@d,ok")
    assert any("Invalid file extension" in error for error in errors)

    errors = validators.validate_extensions_input("toolongexts")
    assert any("File extension too long" in error for error in errors)

    assert validators.validate_threads_input(1) == []
    errors = validators.validate_threads_input(0)
    assert "Threads must be a positive integer" in errors

    errors = validators.validate_threads_input(51)
    assert "Too many threads" in errors[0]

    errors = validators.validate_threads_input("bad")  # type: ignore[arg-type]
    assert "Threads must be a positive integer" in errors

    with pytest.raises(SystemExit):
        validators.validate_input_mode(None, None)

    with pytest.raises(SystemExit):
        validators.validate_input_mode(str(tmp_path), str(tmp_path))

    missing_file = tmp_path / "missing.bin"
    with pytest.raises(SystemExit):
        validators.validate_single_file(str(missing_file))

    with pytest.raises(SystemExit):
        validators.validate_single_file(str(tmp_path))


def test_xor_sanitization_and_display_errors(capsys: pytest.CaptureFixture[str]) -> None:
    assert validators.sanitize_xor_string(None) is None
    assert validators.sanitize_xor_string("ABC") == "ABC"

    long_input = "A" * 200
    assert len(validators.sanitize_xor_string(long_input) or "") == 100

    assert validators.handle_xor_input("%%%") is None
    validators.display_validation_errors(["error one"])
    output = capsys.readouterr().out
    assert "error one" in output
