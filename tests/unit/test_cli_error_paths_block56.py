from __future__ import annotations

import sys
from io import StringIO
from pathlib import Path

import pytest

from r2inspect.cli.commands.analyze_command import AnalyzeCommand
from r2inspect.cli.commands.base import CommandContext
from r2inspect.cli.commands.batch_command import BatchCommand
from r2inspect.cli.interactive import run_interactive_mode
from r2inspect.factory import create_inspector


def test_analyze_command_error_paths(capsys):
    cmd = AnalyzeCommand(CommandContext.create())

    args = {
        "filename": "/nonexistent/file.bin",
        "config": None,
        "yara": None,
        "xor": None,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "verbose": False,
        "threads": None,
    }
    assert cmd.execute(args) == 1
    out = capsys.readouterr().out
    assert "Analysis failed" in out

    args_verbose = dict(args)
    args_verbose["verbose"] = True
    assert cmd.execute(args_verbose) == 1
    out = capsys.readouterr().out
    assert "Error:" in out


def test_batch_command_error_paths(capsys):
    cmd = BatchCommand(CommandContext.create())
    args = {
        "batch": "/nonexistent/dir",
        "config": None,
        "yara": None,
        "xor": None,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": "exe",
        "threads": 1,
        "verbose": False,
        "quiet": False,
    }
    # This should fail early when finding files
    assert cmd.execute(args) == 0

    args_quiet = dict(args)
    args_quiet["quiet"] = True
    assert cmd.execute(args_quiet) == 0

    # Force error handling in batch command
    args_bad = dict(args)
    args_bad["batch"] = None  # type: ignore[assignment]
    assert cmd.execute(args_bad) == 1
    out = capsys.readouterr().out
    assert "Batch analysis failed" in out


def test_interactive_mode_eof_and_interrupt():
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")

    # Empty command path
    old_stdin = sys.stdin
    sys.stdin = StringIO("\nquit\n")
    try:
        with create_inspector(str(sample)) as inspector:
            run_interactive_mode(inspector, {})
    finally:
        sys.stdin = old_stdin

    # EOF path
    old_stdin = sys.stdin
    sys.stdin = StringIO("")
    try:
        with create_inspector(str(sample)) as inspector:
            run_interactive_mode(inspector, {})
    finally:
        sys.stdin = old_stdin

    # KeyboardInterrupt path via custom stdin
    class _InterruptStdin:
        def readline(self, *_args, **_kwargs):
            raise KeyboardInterrupt

    sys.stdin = _InterruptStdin()  # type: ignore[assignment]
    try:
        with create_inspector(str(sample)) as inspector:
            run_interactive_mode(inspector, {})
    finally:
        sys.stdin = old_stdin
