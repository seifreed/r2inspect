from __future__ import annotations

import sys
from io import StringIO
from pathlib import Path

import pytest

from r2inspect.cli import interactive
from r2inspect.cli.commands.base import CommandContext
from r2inspect.cli.commands.interactive_command import InteractiveCommand
from r2inspect.factory import create_inspector


def _sample_path() -> Path:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")
    return sample


def test_run_interactive_mode_inprocess_commands(capsys):
    sample = _sample_path()
    options = {
        "detect_packer": False,
        "detect_crypto": False,
        "analyze_functions": False,
    }

    old_stdin = sys.stdin
    sys.stdin = StringIO(
        "info\n"
        "pe\n"
        "imports\n"
        "exports\n"
        "sections\n"
        "strings\n"
        "analyze\n"
        "unknown\n"
        "help\n"
        "quit\n"
    )
    buffer = StringIO()
    original_file = interactive.console.file
    try:
        with create_inspector(str(sample)) as inspector:
            interactive.console.file = buffer
            interactive.run_interactive_mode(inspector, options)
    finally:
        interactive.console.file = original_file
        sys.stdin = old_stdin

    out = buffer.getvalue()
    assert "Interactive Mode" in out
    assert "Unknown command" in out
    assert "Exiting interactive mode" in out


def test_interactive_command_run_loop_inprocess(capsys):
    sample = _sample_path()
    options = {
        "detect_packer": False,
        "detect_crypto": False,
        "analyze_functions": False,
    }

    cmd = InteractiveCommand(CommandContext.create())

    old_stdin = sys.stdin
    sys.stdin = StringIO("help\nunknown\n\nquit\n")
    buffer = StringIO()
    original_file = cmd.context.console.file
    try:
        with create_inspector(str(sample)) as inspector:
            cmd.context.console.file = buffer
            cmd._run_interactive_mode(inspector, options)
    finally:
        cmd.context.console.file = original_file
        sys.stdin = old_stdin

    out = buffer.getvalue()
    assert "Interactive Mode" in out
    assert "Unknown command" in out


def test_interactive_command_handlers_real(capsys):
    sample = _sample_path()
    cmd = InteractiveCommand(CommandContext.create())

    buffer = StringIO()
    original_file = cmd.context.console.file
    try:
        with create_inspector(str(sample)) as inspector:
            cmd.context.console.file = buffer
            cmd._cmd_strings(inspector)
            cmd._cmd_info(inspector)
            cmd._cmd_pe(inspector)
            cmd._cmd_imports(inspector)
            cmd._cmd_exports(inspector)
            cmd._cmd_sections(inspector)
    finally:
        cmd.context.console.file = original_file

    out = buffer.getvalue()
    assert "Extracting strings" in out
    assert "File Information" in out
    assert "PE Information" in out


def test_interactive_command_analyze_real(capsys):
    sample = _sample_path()
    cmd = InteractiveCommand(CommandContext.create())
    options = {
        "detect_packer": False,
        "detect_crypto": False,
        "analyze_functions": False,
    }

    from r2inspect.cli.display import display_results

    buffer = StringIO()
    original_file = cmd.context.console.file
    try:
        with create_inspector(str(sample)) as inspector:
            cmd.context.console.file = buffer
            cmd._cmd_analyze(inspector, options, display_results)
    finally:
        cmd.context.console.file = original_file

    out = buffer.getvalue()
    assert "Running full analysis" in out
