from __future__ import annotations

import io
from pathlib import Path

import pytest

from r2inspect import cli_main
from r2inspect.cli import display


def _base_args() -> dict[str, object]:
    return {
        "filename": None,
        "interactive": False,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "xor": None,
        "verbose": False,
        "quiet": False,
        "config": None,
        "yara": None,
        "batch": None,
        "extensions": None,
        "list_yara": False,
        "threads": 1,
        "version": False,
    }


def _sample_path() -> Path:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")
    return sample


@pytest.mark.unit
def test_run_cli_validation_errors_exit_nonzero() -> None:
    args = cli_main.CLIArgs(**{**_base_args(), "filename": "missing_file.exe"})
    with pytest.raises(SystemExit) as exc:
        cli_main.run_cli(args)
    assert exc.value.code == 1


@pytest.mark.unit
def test_run_cli_prints_banner_when_not_quiet() -> None:
    sample = _sample_path()
    args = cli_main.CLIArgs(
        **{
            **_base_args(),
            "filename": str(sample),
            "quiet": False,
            "output_json": False,
            "output_csv": False,
        }
    )

    buffer = io.StringIO()
    original_file = display.console.file
    try:
        display.console.file = buffer
        with pytest.raises(SystemExit) as exc:
            cli_main.run_cli(args)
        assert exc.value.code == 0
    finally:
        display.console.file = original_file

    output = buffer.getvalue()
    assert "Advanced Malware Analysis Tool" in output
