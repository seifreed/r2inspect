"""
Tests for r2inspect/cli/commands/interactive_command.py - coverage without mocks.

Covers execute(), _run_interactive_mode(), all interactive command handlers,
_handle_error(), _display_welcome(), and _should_exit().
"""

from __future__ import annotations

import sys
from io import StringIO
from pathlib import Path

import pytest

from r2inspect.cli.commands.base import CommandContext
from r2inspect.cli.commands.interactive_command import InteractiveCommand
from r2inspect.factory import create_inspector


def _sample() -> Path:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")
    return sample


# ---------------------------------------------------------------------------
# _should_exit
# ---------------------------------------------------------------------------


def test_should_exit_quit():
    cmd = InteractiveCommand(CommandContext.create())
    assert cmd._should_exit("quit") is True


def test_should_exit_exit():
    cmd = InteractiveCommand(CommandContext.create())
    assert cmd._should_exit("exit") is True


def test_should_exit_q():
    cmd = InteractiveCommand(CommandContext.create())
    assert cmd._should_exit("q") is True


def test_should_exit_other():
    cmd = InteractiveCommand(CommandContext.create())
    assert cmd._should_exit("analyze") is False
    assert cmd._should_exit("") is False
    assert cmd._should_exit("help") is False


# ---------------------------------------------------------------------------
# _display_welcome
# ---------------------------------------------------------------------------


def test_display_welcome_prints_all_commands(capsys):
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf
    cmd._display_welcome()
    out = buf.getvalue()
    assert "analyze" in out
    assert "strings" in out
    assert "help" in out
    assert "quit" in out


# ---------------------------------------------------------------------------
# _handle_error
# ---------------------------------------------------------------------------


def test_handle_error_not_verbose_shows_brief_message(capsys):
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf
    cmd._handle_error(RuntimeError("test error"), verbose=False)
    out = buf.getvalue()
    assert "interactive mode failed" in out.lower() or "failed" in out.lower()


def test_handle_error_verbose_shows_full_traceback(capsys):
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf
    cmd._handle_error(ValueError("bad value"), verbose=True)
    out = buf.getvalue()
    assert "error" in out.lower()


# ---------------------------------------------------------------------------
# _run_interactive_mode - all commands
# ---------------------------------------------------------------------------


def test_run_interactive_mode_quit_on_first_command():
    sample = _sample()
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf

    old_stdin = sys.stdin
    sys.stdin = StringIO("quit\n")
    try:
        with create_inspector(str(sample)) as inspector:
            cmd._run_interactive_mode(inspector, {})
    finally:
        sys.stdin = old_stdin

    out = buf.getvalue()
    assert "exiting" in out.lower() or "interactive" in out.lower()


def test_run_interactive_mode_empty_command_ignored():
    sample = _sample()
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf

    old_stdin = sys.stdin
    sys.stdin = StringIO("\n\nquit\n")
    try:
        with create_inspector(str(sample)) as inspector:
            cmd._run_interactive_mode(inspector, {})
    finally:
        sys.stdin = old_stdin


def test_run_interactive_mode_eof_exits_cleanly():
    sample = _sample()
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf

    old_stdin = sys.stdin
    sys.stdin = StringIO("")  # EOF immediately
    try:
        with create_inspector(str(sample)) as inspector:
            cmd._run_interactive_mode(inspector, {})
    finally:
        sys.stdin = old_stdin

    out = buf.getvalue()
    assert "exiting" in out.lower() or "interactive" in out.lower()


def test_run_interactive_mode_help_command():
    sample = _sample()
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf

    old_stdin = sys.stdin
    sys.stdin = StringIO("help\nquit\n")
    try:
        with create_inspector(str(sample)) as inspector:
            cmd._run_interactive_mode(inspector, {})
    finally:
        sys.stdin = old_stdin

    out = buf.getvalue()
    assert "analyze" in out


def test_run_interactive_mode_unknown_command_shows_error():
    sample = _sample()
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf

    old_stdin = sys.stdin
    sys.stdin = StringIO("notacommand\nquit\n")
    try:
        with create_inspector(str(sample)) as inspector:
            cmd._run_interactive_mode(inspector, {})
    finally:
        sys.stdin = old_stdin

    out = buf.getvalue()
    assert "unknown command" in out.lower() or "notacommand" in out.lower()


def test_run_interactive_mode_all_commands():
    sample = _sample()
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf

    old_stdin = sys.stdin
    sys.stdin = StringIO(
        "info\n"
        "pe\n"
        "imports\n"
        "exports\n"
        "sections\n"
        "strings\n"
        "help\n"
        "exit\n"
    )
    try:
        with create_inspector(str(sample)) as inspector:
            cmd._run_interactive_mode(inspector, {})
    finally:
        sys.stdin = old_stdin

    out = buf.getvalue()
    assert "exiting" in out.lower() or "interactive" in out.lower()


# ---------------------------------------------------------------------------
# _cmd_* individual handler tests
# ---------------------------------------------------------------------------


def test_cmd_strings(capsys):
    sample = _sample()
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf

    with create_inspector(str(sample)) as inspector:
        cmd._cmd_strings(inspector)

    out = buf.getvalue()
    assert "extracting strings" in out.lower()


def test_cmd_info(capsys):
    sample = _sample()
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf

    with create_inspector(str(sample)) as inspector:
        cmd._cmd_info(inspector)

    out = buf.getvalue()
    assert "file information" in out.lower() or len(out) > 0


def test_cmd_pe(capsys):
    sample = _sample()
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf

    with create_inspector(str(sample)) as inspector:
        cmd._cmd_pe(inspector)

    out = buf.getvalue()
    assert "pe information" in out.lower() or len(out) > 0


def test_cmd_imports(capsys):
    sample = _sample()
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf

    with create_inspector(str(sample)) as inspector:
        cmd._cmd_imports(inspector)


def test_cmd_exports(capsys):
    sample = _sample()
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf

    with create_inspector(str(sample)) as inspector:
        cmd._cmd_exports(inspector)


def test_cmd_sections(capsys):
    sample = _sample()
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf

    with create_inspector(str(sample)) as inspector:
        cmd._cmd_sections(inspector)


def test_cmd_analyze():
    sample = _sample()
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf

    from r2inspect.cli.display import display_results

    with create_inspector(str(sample)) as inspector:
        cmd._cmd_analyze(
            inspector,
            {"detect_packer": False, "detect_crypto": False, "analyze_functions": False},
            display_results,
        )

    out = buf.getvalue()
    assert "running full analysis" in out.lower()


# ---------------------------------------------------------------------------
# execute() - covers line 94 (return 0 on success)
# ---------------------------------------------------------------------------


def test_execute_succeeds_and_returns_zero():
    sample = _sample()
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf

    old_stdin = sys.stdin
    sys.stdin = StringIO("quit\n")
    try:
        result = cmd.execute(
            {
                "filename": str(sample),
                "config": None,
                "yara": None,
                "xor": None,
                "verbose": False,
            }
        )
    finally:
        sys.stdin = old_stdin

    assert result == 0


def test_execute_returns_one_on_error():
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf

    # Provide a non-existent file - create_inspector will raise, execute returns 1
    result = cmd.execute(
        {
            "filename": "/no/such/file.exe",
            "config": None,
            "yara": None,
            "xor": None,
            "verbose": False,
        }
    )

    assert result == 1


def test_execute_verbose_error_shows_traceback():
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf

    result = cmd.execute(
        {
            "filename": "/no/such/file.exe",
            "config": None,
            "yara": None,
            "xor": None,
            "verbose": True,
        }
    )

    assert result == 1
    out = buf.getvalue()
    assert "error" in out.lower()


def test_execute_with_yara_and_xor_options():
    sample = _sample()
    cmd = InteractiveCommand(CommandContext.create())
    buf = StringIO()
    cmd.context.console.file = buf

    old_stdin = sys.stdin
    sys.stdin = StringIO("q\n")
    try:
        result = cmd.execute(
            {
                "filename": str(sample),
                "config": None,
                "yara": None,
                "xor": "testkey",
                "verbose": False,
            }
        )
    finally:
        sys.stdin = old_stdin

    assert result == 0
