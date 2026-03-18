"""Tests for cli/commands/interactive_command.py - targeting uncovered handlers.

NO mocks, NO @patch. Uses real Console(file=StringIO()), real CommandContext,
and a FakeInspector stub.
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


def _make_context(*, verbose: bool = False) -> CommandContext:
    console = Console(file=StringIO(), force_terminal=True)
    return CommandContext(
        console=console,
        logger=logging.getLogger("r2inspect.test.interactive_handlers"),
        config=None,
        verbose=verbose,
        quiet=True,
    )


class FakeInspector:
    """Lightweight inspector stand-in."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def get_strings(self) -> list[str]:
        self.calls.append("get_strings")
        return ["test_string"]

    def get_file_info(self) -> dict[str, Any]:
        self.calls.append("get_file_info")
        return {"name": "test.exe"}

    def get_pe_info(self) -> dict[str, Any]:
        self.calls.append("get_pe_info")
        return {"format": "PE32"}

    def get_imports(self) -> list[str]:
        self.calls.append("get_imports")
        return ["kernel32.dll"]

    def get_exports(self) -> list[str]:
        self.calls.append("get_exports")
        return ["Export1"]

    def get_sections(self) -> list[dict[str, Any]]:
        self.calls.append("get_sections")
        return [{"name": ".text"}]

    def __enter__(self) -> FakeInspector:
        return self

    def __exit__(self, *_: Any) -> bool:
        return False


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_interactive_command_should_exit():
    """Test exit command detection."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)

    assert cmd._should_exit("quit") is True
    assert cmd._should_exit("exit") is True
    assert cmd._should_exit("q") is True
    assert cmd._should_exit("analyze") is False
    assert cmd._should_exit("") is False


def test_interactive_command_display_welcome():
    """Test welcome message display."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    cmd._display_welcome()
    output = ctx.console.file.getvalue()
    assert "analyze" in output.lower()
    assert "strings" in output.lower()


def test_interactive_command_cmd_strings():
    """Test strings command handler."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()
    cmd._cmd_strings(inspector)
    assert "get_strings" in inspector.calls
    output = ctx.console.file.getvalue()
    assert len(output) > 0


def test_interactive_command_cmd_info():
    """Test info command handler."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()
    cmd._cmd_info(inspector)
    assert "get_file_info" in inspector.calls


def test_interactive_command_cmd_pe():
    """Test PE info command handler."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()
    cmd._cmd_pe(inspector)
    assert "get_pe_info" in inspector.calls


def test_interactive_command_cmd_imports():
    """Test imports command handler."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()
    cmd._cmd_imports(inspector)
    assert "get_imports" in inspector.calls


def test_interactive_command_cmd_exports():
    """Test exports command handler."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()
    cmd._cmd_exports(inspector)
    assert "get_exports" in inspector.calls


def test_interactive_command_cmd_sections():
    """Test sections command handler."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()
    cmd._cmd_sections(inspector)
    assert "get_sections" in inspector.calls


def test_interactive_command_execute_interactive_command_unknown():
    """Test unknown command handling."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()
    cmd._execute_interactive_command("unknown_command", inspector, {})
    output = ctx.console.file.getvalue()
    assert "Unknown command" in output


def test_interactive_command_execute_interactive_command_help():
    """Test help command through execute."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()
    cmd._execute_interactive_command("help", inspector, {})
    output = ctx.console.file.getvalue()
    assert len(output) > 0


def test_interactive_command_handle_error_verbose():
    """Test error handling with verbose flag."""
    ctx = _make_context(verbose=True)
    cmd = InteractiveCommand(ctx)
    error = RuntimeError("Test error")
    cmd._handle_error(error, verbose=True)
    output = ctx.console.file.getvalue()
    assert "Test error" in output


def test_interactive_command_handle_error_non_verbose():
    """Test error handling without verbose flag."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    error = RuntimeError("Test error")
    cmd._handle_error(error, verbose=False)
    output = ctx.console.file.getvalue()
    assert "Test error" in output


def test_interactive_command_execute_all_commands():
    """Test executing all interactive commands sequentially."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()

    commands = ["strings", "info", "pe", "imports", "exports", "sections", "help"]
    for command in commands:
        cmd._execute_interactive_command(command, inspector, {})


def test_interactive_command_eof_error():
    """Test EOF error handling in run_interactive_mode."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()

    _orig_input = builtins.input
    try:
        builtins.input = lambda _prompt="": (_ for _ in ()).throw(EOFError())
        cmd._run_interactive_mode(inspector, {})
    finally:
        builtins.input = _orig_input


def test_interactive_command_keyboard_interrupt():
    """Test keyboard interrupt handling in run_interactive_mode."""
    ctx = _make_context()
    cmd = InteractiveCommand(ctx)
    inspector = FakeInspector()

    _orig_input = builtins.input
    try:
        builtins.input = lambda _prompt="": (_ for _ in ()).throw(KeyboardInterrupt())
        cmd._run_interactive_mode(inspector, {})
    finally:
        builtins.input = _orig_input
