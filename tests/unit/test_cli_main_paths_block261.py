from __future__ import annotations

import io
import runpy
import sys
from pathlib import Path

import pytest

from r2inspect import cli_main
from r2inspect.cli.commands import CommandContext


def _make_args(**overrides):
    base = {
        "filename": None,
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
    base.update(overrides)
    return cli_main.CLIArgs(**base)


def test_execute_version_exits():
    with pytest.raises(SystemExit) as exc:
        cli_main._execute_version()
    assert exc.value.code == 0


def test_execute_list_yara_exits(tmp_path: Path):
    with pytest.raises(SystemExit):
        cli_main._execute_list_yara(config=None, yara=None)


def test_run_cli_validation_errors():
    args = _make_args(filename="/nonexistent/file.bin")
    with pytest.raises(SystemExit) as exc:
        cli_main.run_cli(args)
    assert exc.value.code == 1


def test_dispatch_command_batch(tmp_path: Path):
    context = cli_main._build_context(verbose=False, quiet=True, batch=str(tmp_path))
    args = _make_args(batch=str(tmp_path), output_json=False, output_csv=False)
    with pytest.raises(SystemExit) as exc:
        cli_main._dispatch_command(context, args)
    assert exc.value.code == 0


def test_dispatch_command_interactive_quit(samples_dir: Path):
    context = cli_main._build_context(verbose=False, quiet=True, batch=None)
    sample = samples_dir / "hello_pe.exe"
    args = _make_args(filename=str(sample), interactive=True)

    old_stdin = sys.stdin
    sys.stdin = io.StringIO("quit\n")
    try:
        with pytest.raises(SystemExit) as exc:
            cli_main._dispatch_command(context, args)
        assert exc.value.code == 0
    finally:
        sys.stdin = old_stdin


def test_cli_main_module_entrypoint():
    old_argv = sys.argv
    sys.argv = ["r2inspect", "--version"]
    try:
        with pytest.raises(SystemExit):
            runpy.run_module("r2inspect", run_name="__main__")
    finally:
        sys.argv = old_argv
