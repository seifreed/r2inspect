"""Tests for cli/interactive.py - targeting uncovered code paths.

NO mocks, NO @patch. Uses a real Console(file=StringIO()) and
a FakeInspector stub to exercise interactive mode functions.
"""

from __future__ import annotations

import builtins
from io import StringIO
from typing import Any

from rich.console import Console

import r2inspect.cli.interactive as interactive_mod
from r2inspect.cli.interactive import (
    _print_help,
    run_interactive_mode,
    show_strings_only,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeInspector:
    """Lightweight inspector stand-in for interactive mode."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def get_strings(self) -> list[str]:
        self.calls.append("get_strings")
        return ["suspicious_string", "http://example.com"]

    def get_file_info(self) -> dict[str, Any]:
        self.calls.append("get_file_info")
        return {"name": "malware.exe", "size": 12345, "md5": "abc123"}

    def get_pe_info(self) -> dict[str, Any]:
        self.calls.append("get_pe_info")
        return {"format": "PE32", "architecture": "x86"}

    def get_imports(self) -> list[str]:
        self.calls.append("get_imports")
        return ["kernel32.dll!CreateProcess", "ws2_32.dll!connect"]

    def get_exports(self) -> list[str]:
        self.calls.append("get_exports")
        return ["DllMain", "StartService"]

    def get_sections(self) -> list[dict[str, Any]]:
        self.calls.append("get_sections")
        return [{"name": ".text", "size": 4096}, {"name": ".data", "size": 2048}]


def _with_fake_console(fn):
    """Replace the module-level console with a StringIO-backed one, restore after."""
    original_console = interactive_mod.console
    fake_console = Console(file=StringIO(), force_terminal=True)
    interactive_mod.console = fake_console
    try:
        fn(fake_console)
    finally:
        interactive_mod.console = original_console


def _run_with_inputs(inspector: FakeInspector, options: dict[str, Any], inputs: list[str]) -> str:
    """Run interactive mode with canned inputs and return console output."""
    original_console = interactive_mod.console
    fake_console = Console(file=StringIO(), force_terminal=True)
    interactive_mod.console = fake_console

    cmds_iter = iter(inputs)
    _orig_input = builtins.input
    try:
        builtins.input = lambda _prompt="": next(cmds_iter)
        run_interactive_mode(inspector, options)
    except StopIteration:
        pass
    finally:
        builtins.input = _orig_input
        interactive_mod.console = original_console

    return fake_console.file.getvalue()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_show_strings_only():
    """Test strings-only display function."""
    inspector = FakeInspector()

    def _check(console: Console) -> None:
        show_strings_only(inspector)
        assert "get_strings" in inspector.calls
        output = console.file.getvalue()
        assert "suspicious_string" in output

    _with_fake_console(_check)


def test_print_help():
    """Test help command display."""

    def _check(console: Console) -> None:
        _print_help()
        output = console.file.getvalue()
        assert "analyze" in output
        assert "strings" in output

    _with_fake_console(_check)


def test_run_interactive_mode_quit_command():
    """Test interactive mode with quit command."""
    inspector = FakeInspector()
    output = _run_with_inputs(inspector, {}, ["quit"])
    assert "Exiting" in output


def test_run_interactive_mode_exit_command():
    """Test interactive mode with exit command."""
    inspector = FakeInspector()
    output = _run_with_inputs(inspector, {}, ["exit"])
    assert "Exiting" in output


def test_run_interactive_mode_empty_command():
    """Test interactive mode with empty command (just Enter)."""
    inspector = FakeInspector()
    output = _run_with_inputs(inspector, {}, ["", "", "quit"])
    assert "Exiting" in output


def test_run_interactive_mode_unknown_command():
    """Test interactive mode with unknown command."""
    inspector = FakeInspector()
    output = _run_with_inputs(inspector, {}, ["invalid_cmd", "quit"])
    assert "Unknown command" in output


def test_run_interactive_mode_help_command():
    """Test interactive mode help command."""
    inspector = FakeInspector()
    output = _run_with_inputs(inspector, {}, ["help", "quit"])
    assert "analyze" in output.lower()


def test_run_interactive_mode_strings_command():
    """Test interactive mode strings command."""
    inspector = FakeInspector()
    _output = _run_with_inputs(inspector, {}, ["strings", "quit"])
    assert "get_strings" in inspector.calls


def test_run_interactive_mode_info_command():
    """Test interactive mode info command."""
    inspector = FakeInspector()
    _output = _run_with_inputs(inspector, {}, ["info", "quit"])
    assert "get_file_info" in inspector.calls


def test_run_interactive_mode_pe_command():
    """Test interactive mode PE command."""
    inspector = FakeInspector()
    _output = _run_with_inputs(inspector, {}, ["pe", "quit"])
    assert "get_pe_info" in inspector.calls


def test_run_interactive_mode_imports_command():
    """Test interactive mode imports command."""
    inspector = FakeInspector()
    _output = _run_with_inputs(inspector, {}, ["imports", "quit"])
    assert "get_imports" in inspector.calls


def test_run_interactive_mode_exports_command():
    """Test interactive mode exports command."""
    inspector = FakeInspector()
    _output = _run_with_inputs(inspector, {}, ["exports", "quit"])
    assert "get_exports" in inspector.calls


def test_run_interactive_mode_sections_command():
    """Test interactive mode sections command."""
    inspector = FakeInspector()
    _output = _run_with_inputs(inspector, {}, ["sections", "quit"])
    assert "get_sections" in inspector.calls


def test_run_interactive_mode_eof_error():
    """Test interactive mode with EOF (Ctrl+D)."""
    inspector = FakeInspector()
    original_console = interactive_mod.console
    fake_console = Console(file=StringIO(), force_terminal=True)
    interactive_mod.console = fake_console

    _orig_input = builtins.input
    try:
        builtins.input = lambda _prompt="": (_ for _ in ()).throw(EOFError())
        run_interactive_mode(inspector, {})
    finally:
        builtins.input = _orig_input
        interactive_mod.console = original_console


def test_run_interactive_mode_keyboard_interrupt():
    """Test interactive mode with Ctrl+C."""
    inspector = FakeInspector()
    original_console = interactive_mod.console
    fake_console = Console(file=StringIO(), force_terminal=True)
    interactive_mod.console = fake_console

    _orig_input = builtins.input
    try:
        builtins.input = lambda _prompt="": (_ for _ in ()).throw(KeyboardInterrupt())
        run_interactive_mode(inspector, {})
    finally:
        builtins.input = _orig_input
        interactive_mod.console = original_console
