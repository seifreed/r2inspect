import sys
from pathlib import Path

import pytest

from r2inspect.cli.validators import (
    handle_xor_input,
    sanitize_xor_string,
    validate_batch_input,
    validate_config_input,
    validate_extensions_input,
    validate_file_input,
    validate_input_mode,
    validate_output_input,
    validate_threads_input,
)


def test_validate_file_input(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")
    assert validate_file_input(str(sample)) == []

    assert validate_file_input(str(tmp_path / "missing.bin"))


def test_validate_batch_input(tmp_path):
    assert validate_batch_input(str(tmp_path)) == []
    assert validate_batch_input(str(tmp_path / "missing"))


def test_validate_output_input(tmp_path):
    output_file = tmp_path / "out.txt"
    output_file.write_text("x")
    assert validate_output_input(str(output_file)) == []


def test_validate_config_input(tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text("{}")
    assert validate_config_input(str(cfg)) == []
    bad = tmp_path / "config.exe"
    bad.write_text("x")
    assert validate_config_input(str(bad))


def test_validate_extensions_input():
    assert validate_extensions_input("exe, dll") == []
    assert validate_extensions_input("bad@")


def test_validate_threads_input():
    assert validate_threads_input(4) == []
    assert validate_threads_input(0)
    assert validate_threads_input(100)


def test_validate_input_mode_exits(tmp_path, capsys):
    missing = str(tmp_path / "missing.bin")
    with pytest.raises(SystemExit):
        validate_input_mode(None, None)
    with pytest.raises(SystemExit):
        validate_input_mode("a", "b")
    with pytest.raises(SystemExit):
        validate_input_mode(missing, None)


def test_sanitize_xor_string():
    assert sanitize_xor_string("abc123") == "abc123"
    assert sanitize_xor_string("@@@") is None


def test_handle_xor_input():
    assert handle_xor_input("abc") == "abc"
    assert handle_xor_input("@@@") is None
