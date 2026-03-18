from __future__ import annotations

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
    validate_threads_input,
    validate_yara_input,
)


def test_validate_file_batch_and_output_inputs_cover_success_and_failure_paths(
    tmp_path: Path,
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 200)
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")

    assert validate_file_input(str(sample)) == []
    assert any("empty" in error.lower() for error in validate_file_input(str(empty)))
    assert any(
        "not a regular file" in error.lower() for error in validate_file_input(str(tmp_path))
    )

    assert validate_batch_input(str(tmp_path)) == []
    assert any("not a directory" in error.lower() for error in validate_batch_input(str(sample)))

    writable_output = tmp_path / "out.json"
    writable_output.write_text("{}")
    assert validate_output_input(str(writable_output)) == []


def test_validate_yara_config_extensions_and_threads_behave_consistently(tmp_path: Path) -> None:
    yara_dir = tmp_path / "rules"
    yara_dir.mkdir()
    config = tmp_path / "config.json"
    config.write_text("{}")

    assert validate_yara_input(str(yara_dir)) == []
    assert validate_config_input(str(config)) == []
    assert validate_extensions_input("exe,dll") == []
    assert validate_threads_input(4) == []

    invalid_ext_errors = validate_extensions_input("exe@, dll#")
    assert len(invalid_ext_errors) >= 2
    assert any("invalid file extension" in error.lower() for error in invalid_ext_errors)
    assert any("too many threads" in error.lower() for error in validate_threads_input(51))


def test_xor_and_validation_aggregation_behaviors(tmp_path: Path, capsys) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 200)
    config = tmp_path / "config.toml"
    config.write_text('[section]\nkey = "value"')

    assert sanitize_xor_string("abc_XY-12.Z ") == "abc_XY-12.Z "
    assert sanitize_xor_string("@#$%^&*()") is None
    assert handle_xor_input("mykey123") == "mykey123"
    assert handle_xor_input("@#$%^&*()") is None

    display_validation_errors(["Error A", "Error B"])
    assert "Error A" in capsys.readouterr().out

    errors = validate_inputs(
        filename=str(sample),
        batch=None,
        output=None,
        yara=None,
        config=str(config),
        extensions="exe,dll",
        threads=4,
    )
    assert errors == []


def test_validate_input_mode_enforces_single_mode(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 10)

    validate_input_mode(str(sample), None)
    validate_input_mode(None, str(tmp_path))

    with pytest.raises(SystemExit):
        validate_input_mode(None, None)

    with pytest.raises(SystemExit):
        validate_input_mode(str(sample), str(tmp_path))
