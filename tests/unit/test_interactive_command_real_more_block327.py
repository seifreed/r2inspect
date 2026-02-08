from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from r2inspect.cli.commands.base import CommandContext
from r2inspect.cli.commands.interactive_command import InteractiveCommand
from r2inspect.factory import create_inspector


def _sample_path() -> Path:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")
    return sample


@pytest.mark.unit
def test_interactive_command_real_handlers() -> None:
    sample = _sample_path()
    context = CommandContext.create(config=None, verbose=False, quiet=True, thread_safe=False)
    command = InteractiveCommand(context)

    buffer = io.StringIO()
    original_file = command.context.console.file
    try:
        command.context.console.file = buffer
        with create_inspector(str(sample)) as inspector:
            command._cmd_info(inspector)
            command._cmd_pe(inspector)
            command._cmd_sections(inspector)
            command._cmd_imports(inspector)
            command._cmd_exports(inspector)
            command._cmd_strings(inspector)

            options = command._setup_analysis_options(yara=None, xor=None)
            command._cmd_analyze(inspector, options, lambda results: results)
    finally:
        command.context.console.file = original_file

    output = buffer.getvalue()
    assert "File Information" in output


@pytest.mark.unit
def test_interactive_command_unknown_command_message() -> None:
    sample = _sample_path()
    context = CommandContext.create(config=None, verbose=False, quiet=True, thread_safe=False)
    command = InteractiveCommand(context)

    buffer = io.StringIO()
    original_file = command.context.console.file
    try:
        command.context.console.file = buffer
        with create_inspector(str(sample)) as inspector:
            command._execute_interactive_command("unknown", inspector, {})
    finally:
        command.context.console.file = original_file

    output = buffer.getvalue()
    assert "Unknown command" in output


@pytest.mark.unit
def test_interactive_command_handle_error_verbose_and_quiet() -> None:
    context = CommandContext.create(config=None, verbose=False, quiet=True, thread_safe=False)
    command = InteractiveCommand(context)

    buffer = io.StringIO()
    original_file = command.context.console.file
    try:
        command.context.console.file = buffer
        command._handle_error(RuntimeError("boom"), verbose=False)
        command._handle_error(RuntimeError("boom"), verbose=True)
    finally:
        command.context.console.file = original_file

    output = buffer.getvalue()
    assert "Interactive mode failed" in output
    assert "Error: boom" in output


@pytest.mark.unit
def test_interactive_command_run_mode_empty_and_error() -> None:
    sample = _sample_path()
    context = CommandContext.create(config=None, verbose=False, quiet=True, thread_safe=False)
    command = InteractiveCommand(context)

    buffer = io.StringIO()
    original_file = command.context.console.file
    original_stdin = sys.stdin
    try:
        command.context.console.file = buffer
        sys.stdin = io.StringIO("\ninfo\nquit\n")
        with create_inspector(str(sample)) as inspector:
            command._run_interactive_mode(inspector, {})

        # Force an error path by using an invalid inspector reference.
        sys.stdin = io.StringIO("info\nquit\n")
        command._run_interactive_mode(None, {})
    finally:
        command.context.console.file = original_file
        sys.stdin = original_stdin

    output = buffer.getvalue()
    assert "Exiting interactive mode" in output
    assert "Command error" in output


@pytest.mark.unit
def test_interactive_command_execute_invalid_file() -> None:
    context = CommandContext.create(config=None, verbose=False, quiet=True, thread_safe=False)
    command = InteractiveCommand(context)

    exit_code = command.execute(
        {
            "filename": "missing_file.exe",
            "config": None,
            "yara": None,
            "xor": None,
            "verbose": False,
        }
    )
    assert exit_code == 1


@pytest.mark.unit
def test_interactive_command_run_mode_eof() -> None:
    sample = _sample_path()
    context = CommandContext.create(config=None, verbose=False, quiet=True, thread_safe=False)
    command = InteractiveCommand(context)

    buffer = io.StringIO()
    original_file = command.context.console.file
    original_stdin = sys.stdin
    try:
        command.context.console.file = buffer
        sys.stdin = io.StringIO("")
        with create_inspector(str(sample)) as inspector:
            command._run_interactive_mode(inspector, {})
    finally:
        command.context.console.file = original_file
        sys.stdin = original_stdin

    output = buffer.getvalue()
    assert "Exiting interactive mode" in output
