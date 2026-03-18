"""Comprehensive tests for interactive_command.py - 100% coverage target.

NO mocks, NO @patch. Uses real Console(file=StringIO()), real CommandContext,
and a FakeInspector stub to exercise all code paths.
"""

from __future__ import annotations

import builtins
import logging
from io import StringIO
from typing import Any

from rich.console import Console

from r2inspect.cli.commands.base import CommandContext
from r2inspect.cli.commands.interactive_command import InteractiveCommand


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_context() -> CommandContext:
    """Build a real CommandContext backed by a StringIO console."""
    console = Console(file=StringIO(), force_terminal=True)
    return CommandContext(
        console=console,
        logger=logging.getLogger("r2inspect.test.interactive_cmd"),
        config=None,
        verbose=False,
        quiet=True,
    )


class FakeInspector:
    """Lightweight inspector stand-in that returns canned data."""

    def get_strings(self) -> list[str]:
        return ["string1", "string2"]

    def get_file_info(self) -> dict[str, Any]:
        return {"name": "test.exe", "size": 1024}

    def get_pe_info(self) -> dict[str, Any]:
        return {"machine": "x86", "format": "PE32"}

    def get_imports(self) -> list[str]:
        return ["kernel32.dll!CreateFileW"]

    def get_exports(self) -> list[str]:
        return ["DllMain"]

    def get_sections(self) -> list[dict[str, Any]]:
        return [{"name": ".text", "size": 4096}]

    def __enter__(self) -> FakeInspector:
        return self

    def __exit__(self, *_: Any) -> bool:
        return False


# ---------------------------------------------------------------------------
# _should_exit
# ---------------------------------------------------------------------------


def test_should_exit():
    """Test _should_exit method."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    assert cmd._should_exit("quit") is True
    assert cmd._should_exit("exit") is True
    assert cmd._should_exit("q") is True
    assert cmd._should_exit("analyze") is False
    assert cmd._should_exit("") is False


# ---------------------------------------------------------------------------
# _display_welcome
# ---------------------------------------------------------------------------


def test_display_welcome():
    """Test _display_welcome method prints to console."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    cmd._display_welcome()
    output = ctx.console.file.getvalue()
    assert "analyze" in output.lower()
    assert "quit" in output.lower()


# ---------------------------------------------------------------------------
# _run_interactive_mode -- quit immediately
# ---------------------------------------------------------------------------


def test_run_interactive_mode_quit():
    """Test _run_interactive_mode with quit."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()

    _orig_input = builtins.input
    try:
        builtins.input = lambda _prompt="": "quit"
        cmd._run_interactive_mode(inspector, {})
    finally:
        builtins.input = _orig_input


def test_run_interactive_mode_empty_then_quit():
    """Test _run_interactive_mode with empty command then quit."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()
    cmds = iter(["", "quit"])

    _orig_input = builtins.input
    try:
        builtins.input = lambda _prompt="": next(cmds)
        cmd._run_interactive_mode(inspector, {})
    finally:
        builtins.input = _orig_input


def test_run_interactive_mode_keyboard_interrupt():
    """Test _run_interactive_mode with KeyboardInterrupt."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()

    def _raise(_prompt=""):
        raise KeyboardInterrupt()

    _orig_input = builtins.input
    try:
        builtins.input = _raise
        cmd._run_interactive_mode(inspector, {})
    finally:
        builtins.input = _orig_input


def test_run_interactive_mode_eof_error():
    """Test _run_interactive_mode with EOFError."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()

    def _raise(_prompt=""):
        raise EOFError()

    _orig_input = builtins.input
    try:
        builtins.input = _raise
        cmd._run_interactive_mode(inspector, {})
    finally:
        builtins.input = _orig_input


def test_run_interactive_mode_exception_in_command():
    """Test _run_interactive_mode with exception during command."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()
    cmds = iter(["unknown_kaboom", "quit"])

    _orig_input = builtins.input
    try:
        builtins.input = lambda _prompt="": next(cmds)
        cmd._run_interactive_mode(inspector, {})
    finally:
        builtins.input = _orig_input


# ---------------------------------------------------------------------------
# _execute_interactive_command (individual commands)
# ---------------------------------------------------------------------------


def test_execute_interactive_command_strings():
    """Test _execute_interactive_command with strings."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()
    cmd._execute_interactive_command("strings", inspector, {})
    output = ctx.console.file.getvalue()
    assert "string1" in output


def test_execute_interactive_command_info():
    """Test _execute_interactive_command with info."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()
    cmd._execute_interactive_command("info", inspector, {})
    output = ctx.console.file.getvalue()
    assert len(output) > 0


def test_execute_interactive_command_pe():
    """Test _execute_interactive_command with pe."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()
    cmd._execute_interactive_command("pe", inspector, {})
    output = ctx.console.file.getvalue()
    assert len(output) > 0


def test_execute_interactive_command_imports():
    """Test _execute_interactive_command with imports."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()
    cmd._execute_interactive_command("imports", inspector, {})
    output = ctx.console.file.getvalue()
    assert "CreateFileW" in output


def test_execute_interactive_command_exports():
    """Test _execute_interactive_command with exports."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()
    cmd._execute_interactive_command("exports", inspector, {})
    output = ctx.console.file.getvalue()
    assert "DllMain" in output


def test_execute_interactive_command_sections():
    """Test _execute_interactive_command with sections."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()
    cmd._execute_interactive_command("sections", inspector, {})
    output = ctx.console.file.getvalue()
    assert len(output) > 0


def test_execute_interactive_command_help():
    """Test _execute_interactive_command with help."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()
    cmd._execute_interactive_command("help", inspector, {})
    output = ctx.console.file.getvalue()
    assert "analyze" in output.lower()


def test_execute_interactive_command_unknown():
    """Test _execute_interactive_command with unknown command."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()
    cmd._execute_interactive_command("unknown_xyz", inspector, {})
    output = ctx.console.file.getvalue()
    assert "Unknown command" in output


# ---------------------------------------------------------------------------
# _handle_error
# ---------------------------------------------------------------------------


def test_handle_error_verbose():
    """Test _handle_error with verbose mode."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    error = RuntimeError("Test error")
    cmd._handle_error(error, verbose=True)
    output = ctx.console.file.getvalue()
    assert "Test error" in output


def test_handle_error_non_verbose():
    """Test _handle_error without verbose mode."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    error = RuntimeError("Test error")
    cmd._handle_error(error, verbose=False)
    output = ctx.console.file.getvalue()
    assert "Test error" in output
    assert "--verbose" in output
