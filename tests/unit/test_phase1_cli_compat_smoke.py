#!/usr/bin/env python3
"""Phase 1 smoke tests: CLI entrypoint and canonical helper surfaces."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from r2inspect import cli_main
from r2inspect.cli.validators import validate_inputs
from r2inspect.error_handling import classifier as error_handler
from r2inspect.infrastructure import command_helpers, r2_helpers, r2_session


def test_cli_smoke_help_version_and_invalid_option() -> None:
    runner = CliRunner()

    help_result = runner.invoke(cli_main.cli, ["--help"])
    assert help_result.exit_code == 0
    assert "Usage:" in help_result.output

    version_result = runner.invoke(cli_main.cli, ["--version"])
    assert version_result.exit_code == 0

    invalid_option = runner.invoke(cli_main.cli, ["--no-such-option"])
    assert invalid_option.exit_code == 2
    assert "No such option" in invalid_option.output

    no_input = runner.invoke(cli_main.cli, [])
    assert no_input.exit_code == 1
    assert "Must provide either a filename or --batch directory" in no_input.output


def test_cli_invalid_option_values_and_threads_validation() -> None:
    runner = CliRunner()

    no_threads = runner.invoke(cli_main.cli, ["--threads", "0"])
    assert no_threads.exit_code == 2
    assert "Invalid value for '--threads'" in no_threads.output

    bad_threads = runner.invoke(cli_main.cli, ["--threads", "51"])
    assert bad_threads.exit_code == 2
    assert "Invalid value for '--threads'" in bad_threads.output


def test_validate_inputs_aggregates_option_errors(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"")

    parent_file = tmp_path / "not_a_dir.txt"
    parent_file.write_text("x", encoding="utf-8")

    output_file = tmp_path / "out.json"
    output_file.write_text("{}", encoding="utf-8")
    output_file.chmod(0o400)

    yara_missing = tmp_path / "missing_rules"
    config_dir = tmp_path / "cfg_dir"
    config_dir.mkdir()

    errors = validate_inputs(
        filename=str(sample),
        batch=str(parent_file),
        output=str(output_file),
        yara=str(yara_missing),
        config=str(config_dir),
        extensions="bad$ext",
        threads=0,
    )

    assert any("File is empty" in error for error in errors)
    assert any("Batch path is not a directory" in error for error in errors)
    if os.name != "nt":
        assert any("Cannot write to output file" in error for error in errors)
    assert any("YARA rules directory does not exist" in error for error in errors)
    assert any("Config path is not a file" in error for error in errors)
    assert any("Invalid file extension" in error for error in errors)
    assert any("Threads must be a positive integer" in error for error in errors)


def test_canonical_helpers_export_expected_symbols() -> None:
    assert callable(command_helpers.cmd)
    assert callable(command_helpers.cmd_list)
    assert callable(command_helpers.cmdj)
    assert "cmd" in command_helpers.__all__
    assert "cmd_list" in command_helpers.__all__
    assert "cmdj" in command_helpers.__all__

    expected_error_exports = {
        "ErrorCategory",
        "ErrorInfo",
        "ErrorClassifier",
        "error_handler",
        "safe_execute",
    }
    assert all(hasattr(error_handler, name) for name in expected_error_exports)

    assert r2_session.R2Session is not None
    assert r2_session.psutil is not None
    assert r2_session.r2pipe is not None


def test_r2_helpers_surface_exists() -> None:
    for name in (
        "safe_cmd",
        "safe_cmd_list",
        "safe_cmd_dict",
        "safe_cmdj",
        "safe_cmdj_any",
        "parse_pe_header_text",
        "get_pe_headers",
        "get_elf_headers",
        "get_macho_headers",
    ):
        assert callable(getattr(r2_helpers, name))


class _RawR2:
    def __init__(self, payload: str) -> None:
        self.payload = payload

    def cmd(self, _command: str) -> str:
        return self.payload

    def cmdj(self, _command: str) -> str:
        raise RuntimeError("intentional failure")


def test_command_helpers_and_r2_helpers_fallback_paths() -> None:
    fallback = _RawR2(payload='{"ok": true}')
    fallback_list = _RawR2(payload='[{"name":"alpha"},{"name":"beta"}]')
    fallback_bad = _RawR2(payload="not json")

    assert command_helpers.cmd(None, fallback, "i") == '{"ok": true}'
    assert command_helpers.cmdj(None, fallback, "i", {"fallback": True}) == {"ok": True}
    assert command_helpers.cmdj(None, fallback_list, "i", []) == [
        {"name": "alpha"},
        {"name": "beta"},
    ]
    assert command_helpers.cmdj(None, fallback_bad, "i", {"fallback": True}) == {"fallback": True}
    assert command_helpers.cmd_list(None, fallback_list, "i") == [
        {"name": "alpha"},
        {"name": "beta"},
    ]
    assert command_helpers.cmd_list(None, fallback_bad, "i") == []
    assert command_helpers.cmd(None, None, "i") == ""
