import runpy
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from r2inspect import cli_main
from r2inspect.__main__ import main as main_entrypoint


@pytest.mark.unit
def test_main_entrypoint_runs_click_help() -> None:
    original_argv = sys.argv[:]
    try:
        sys.argv = ["r2inspect", "--help"]
        with pytest.raises(SystemExit) as exc:
            runpy.run_module("r2inspect.__main__", run_name="__main__")
        assert exc.value.code == 0
    finally:
        sys.argv = original_argv


def test_main_entrypoint_returns_exit_code() -> None:
    original_argv = sys.argv[:]
    try:
        sys.argv = ["r2inspect", "--version"]
        assert main_entrypoint() == 0
    finally:
        sys.argv = original_argv


def test_main_entrypoint_handles_help_flag() -> None:
    original_argv = sys.argv[:]
    try:
        sys.argv = ["r2inspect", "--help"]
        assert main_entrypoint() == 0
    finally:
        sys.argv = original_argv


@pytest.mark.unit
def test_cli_version_and_list_yara_commands() -> None:
    runner = CliRunner()
    result = runner.invoke(cli_main.cli, ["--version"])
    assert result.exit_code == 0

    rules_dir = Path("r2inspect") / "rules" / "yara"
    result = runner.invoke(cli_main.cli, ["--list-yara", "--yara", str(rules_dir)])
    assert result.exit_code == 0


@pytest.mark.unit
def test_cli_validation_error_for_config_extension(tmp_path: Path) -> None:
    bad_config = tmp_path / "config.bad"
    bad_config.write_text("data")

    runner = CliRunner()
    result = runner.invoke(cli_main.cli, ["--config", str(bad_config)])
    assert result.exit_code == 1
    assert "Config file must be JSON" in result.output


class InterruptBool:
    def __bool__(self) -> bool:
        raise KeyboardInterrupt


class BadPath:
    def __bool__(self) -> bool:
        return True

    def __len__(self) -> int:
        raise TypeError("bad length")

    def __contains__(self, _item: object) -> bool:
        raise TypeError("bad contains")


def _base_kwargs(filename: object) -> dict[str, object]:
    return {
        "filename": filename,
        "interactive": False,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "xor": None,
        "verbose": False,
        "quiet": True,
        "config": None,
        "yara": None,
        "batch": None,
        "extensions": None,
        "list_yara": False,
        "threads": 1,
        "version": False,
    }


def test_main_handles_keyboard_interrupt() -> None:
    with pytest.raises(SystemExit) as exc:
        cli_main.main(**_base_kwargs(InterruptBool()))
    assert exc.value.code == 1


def test_main_handles_unexpected_exception() -> None:
    with pytest.raises(SystemExit) as exc:
        cli_main.main(**_base_kwargs(BadPath()))
    assert exc.value.code == 1
