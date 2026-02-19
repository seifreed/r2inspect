"""Tests for InteractiveCommand branch paths in interactive_command.py."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from r2inspect.cli.commands.base import CommandContext
from r2inspect.cli.commands.interactive_command import InteractiveCommand


# ---------------------------------------------------------------------------
# Minimal inspector stub - no mocks
# ---------------------------------------------------------------------------

class InspectorStub:
    """In-memory inspector that satisfies all InteractiveCommand method calls."""

    def analyze(self, **options: object) -> dict:
        return {
            "file_info": {
                "name": "stub.exe",
                "size": 1024,
                "file_type": "PE32",
                "md5": "aabbccdd",
                "sha256": "ee112233",
            }
        }

    def get_strings(self) -> list[str]:
        return ["hello", "world", "stub"]

    def get_file_info(self) -> dict:
        return {"name": "stub.exe", "size": 1024, "type": "PE32"}

    def get_pe_info(self) -> dict:
        return {"imphash": "aabb1234", "is_executable": True}

    def get_imports(self) -> list[str]:
        return ["KERNEL32!CreateFileA", "KERNEL32!ReadFile"]

    def get_exports(self) -> list[str]:
        return ["ExportedFunction"]

    def get_sections(self) -> list[dict]:
        return [
            {
                "name": ".text",
                "raw_size": 4096,
                "flags": "r-x",
                "entropy": 5.5,
                "suspicious_indicators": [],
            },
            {
                "name": ".data",
                "raw_size": 2048,
                "flags": "rw-",
                "entropy": 2.3,
                "suspicious_indicators": ["high_entropy"],
            },
        ]


def _make_cmd() -> InteractiveCommand:
    """Create an InteractiveCommand with a quiet real context."""
    return InteractiveCommand(CommandContext.create(quiet=True))


def _sample_path() -> Path:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary not available")
    return sample


# ---------------------------------------------------------------------------
# _display_welcome
# ---------------------------------------------------------------------------

def test_display_welcome_prints_available_commands() -> None:
    cmd = _make_cmd()
    buf = io.StringIO()
    cmd.context.console.file = buf
    cmd._display_welcome()
    output = buf.getvalue()
    assert "analyze" in output
    assert "quit" in output
    assert "help" in output


# ---------------------------------------------------------------------------
# _should_exit
# ---------------------------------------------------------------------------

def test_should_exit_returns_true_for_quit() -> None:
    cmd = _make_cmd()
    assert cmd._should_exit("quit") is True


def test_should_exit_returns_true_for_exit() -> None:
    cmd = _make_cmd()
    assert cmd._should_exit("exit") is True


def test_should_exit_returns_true_for_q() -> None:
    cmd = _make_cmd()
    assert cmd._should_exit("q") is True


def test_should_exit_returns_false_for_unknown_command() -> None:
    cmd = _make_cmd()
    assert cmd._should_exit("analyze") is False


def test_should_exit_returns_false_for_empty_string() -> None:
    cmd = _make_cmd()
    assert cmd._should_exit("") is False


# ---------------------------------------------------------------------------
# _execute_interactive_command - dispatch to handlers
# ---------------------------------------------------------------------------

def test_execute_interactive_command_unknown_prints_error() -> None:
    cmd = _make_cmd()
    buf = io.StringIO()
    cmd.context.console.file = buf
    cmd._execute_interactive_command("garbage_cmd", InspectorStub(), {})
    assert "Unknown command" in buf.getvalue()


def test_execute_interactive_command_help_calls_display_welcome() -> None:
    cmd = _make_cmd()
    buf = io.StringIO()
    cmd.context.console.file = buf
    cmd._execute_interactive_command("help", InspectorStub(), {})
    assert "Available commands" in buf.getvalue()


def test_execute_interactive_command_strings_prints_strings() -> None:
    cmd = _make_cmd()
    buf = io.StringIO()
    cmd.context.console.file = buf
    cmd._execute_interactive_command("strings", InspectorStub(), {})
    assert "hello" in buf.getvalue()


def test_execute_interactive_command_info_prints_table() -> None:
    cmd = _make_cmd()
    buf = io.StringIO()
    cmd.context.console.file = buf
    cmd._execute_interactive_command("info", InspectorStub(), {})
    output = buf.getvalue()
    assert len(output) > 0


def test_execute_interactive_command_pe_prints_table() -> None:
    cmd = _make_cmd()
    buf = io.StringIO()
    cmd.context.console.file = buf
    cmd._execute_interactive_command("pe", InspectorStub(), {})
    assert len(buf.getvalue()) > 0


def test_execute_interactive_command_imports_prints_imports() -> None:
    cmd = _make_cmd()
    buf = io.StringIO()
    cmd.context.console.file = buf
    cmd._execute_interactive_command("imports", InspectorStub(), {})
    assert "CreateFileA" in buf.getvalue()


def test_execute_interactive_command_exports_prints_exports() -> None:
    cmd = _make_cmd()
    buf = io.StringIO()
    cmd.context.console.file = buf
    cmd._execute_interactive_command("exports", InspectorStub(), {})
    assert "ExportedFunction" in buf.getvalue()


def test_execute_interactive_command_sections_prints_sections() -> None:
    cmd = _make_cmd()
    buf = io.StringIO()
    cmd.context.console.file = buf
    cmd._execute_interactive_command("sections", InspectorStub(), {})
    assert len(buf.getvalue()) > 0


# ---------------------------------------------------------------------------
# _cmd_* methods called directly
# ---------------------------------------------------------------------------

def test_cmd_strings_iterates_all_strings() -> None:
    cmd = _make_cmd()
    buf = io.StringIO()
    cmd.context.console.file = buf
    cmd._cmd_strings(InspectorStub())
    output = buf.getvalue()
    assert "hello" in output
    assert "world" in output
    assert "stub" in output


def test_cmd_strings_handles_empty_list() -> None:
    class EmptyStringInspector(InspectorStub):
        def get_strings(self) -> list[str]:
            return []

    cmd = _make_cmd()
    cmd._cmd_strings(EmptyStringInspector())


def test_cmd_info_calls_format_table() -> None:
    cmd = _make_cmd()
    buf = io.StringIO()
    cmd.context.console.file = buf
    cmd._cmd_info(InspectorStub())
    assert len(buf.getvalue()) > 0


def test_cmd_pe_calls_format_table() -> None:
    cmd = _make_cmd()
    buf = io.StringIO()
    cmd.context.console.file = buf
    cmd._cmd_pe(InspectorStub())
    assert len(buf.getvalue()) > 0


def test_cmd_imports_iterates_all_imports() -> None:
    cmd = _make_cmd()
    buf = io.StringIO()
    cmd.context.console.file = buf
    cmd._cmd_imports(InspectorStub())
    assert "CreateFileA" in buf.getvalue()


def test_cmd_exports_iterates_all_exports() -> None:
    cmd = _make_cmd()
    buf = io.StringIO()
    cmd.context.console.file = buf
    cmd._cmd_exports(InspectorStub())
    assert "ExportedFunction" in buf.getvalue()


def test_cmd_sections_calls_format_sections() -> None:
    cmd = _make_cmd()
    buf = io.StringIO()
    cmd.context.console.file = buf
    cmd._cmd_sections(InspectorStub())
    assert len(buf.getvalue()) > 0


def test_cmd_analyze_runs_analysis_with_no_op_display() -> None:
    cmd = _make_cmd()

    def noop_display(results: dict) -> None:
        pass

    cmd._cmd_analyze(InspectorStub(), {}, noop_display)


def test_cmd_analyze_passes_results_to_display_function() -> None:
    cmd = _make_cmd()
    received: list[dict] = []

    def capture_display(results: dict) -> None:
        received.append(results)

    cmd._cmd_analyze(InspectorStub(), {}, capture_display)
    assert len(received) == 1
    assert "file_info" in received[0]


# ---------------------------------------------------------------------------
# _handle_error
# ---------------------------------------------------------------------------

def test_handle_error_non_verbose_prints_friendly_message() -> None:
    cmd = _make_cmd()
    buf = io.StringIO()
    cmd.context.console.file = buf
    cmd._handle_error(ValueError("something went wrong"), verbose=False)
    output = buf.getvalue()
    assert "Interactive mode failed" in output
    assert "--verbose" in output


def test_handle_error_verbose_prints_full_error() -> None:
    cmd = _make_cmd()
    buf = io.StringIO()
    cmd.context.console.file = buf
    cmd._handle_error(RuntimeError("boom"), verbose=True)
    output = buf.getvalue()
    assert "Error:" in output


# ---------------------------------------------------------------------------
# execute() - error path (invalid file)
# ---------------------------------------------------------------------------

def test_execute_invalid_file_non_verbose_returns_one() -> None:
    cmd = _make_cmd()
    buf = io.StringIO()
    cmd.context.console.file = buf
    result = cmd.execute(
        {
            "filename": "/nonexistent/binary/file.exe",
            "config": None,
            "yara": None,
            "xor": None,
            "verbose": False,
        }
    )
    assert result == 1
    assert "Interactive mode failed" in buf.getvalue()


def test_execute_invalid_file_verbose_returns_one() -> None:
    cmd = _make_cmd()
    buf = io.StringIO()
    cmd.context.console.file = buf
    result = cmd.execute(
        {
            "filename": "/nonexistent/binary/file.exe",
            "config": None,
            "yara": None,
            "xor": None,
            "verbose": True,
        }
    )
    assert result == 1
    assert "Error:" in buf.getvalue()


# ---------------------------------------------------------------------------
# execute() - success path (real sample with immediate EOF on stdin)
# ---------------------------------------------------------------------------

def test_execute_with_real_sample_exits_cleanly_on_eof() -> None:
    sample = _sample_path()
    cmd = _make_cmd()
    original_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO("")  # EOF causes _run_interactive_mode to break immediately
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
        sys.stdin = original_stdin
    assert result == 0


def test_execute_with_real_sample_and_yara_xor_options() -> None:
    sample = _sample_path()
    cmd = _make_cmd()
    original_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO("")
        result = cmd.execute(
            {
                "filename": str(sample),
                "config": None,
                "yara": "rules/yara",
                "xor": "deadbeef",
                "verbose": False,
            }
        )
    finally:
        sys.stdin = original_stdin
    assert result == 0


def test_execute_runs_interactive_loop_help_then_eof() -> None:
    sample = _sample_path()
    cmd = _make_cmd()
    original_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO("help\n")
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
        sys.stdin = original_stdin
    assert result == 0
