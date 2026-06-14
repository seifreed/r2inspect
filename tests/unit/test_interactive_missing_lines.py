from __future__ import annotations

import io
import sys

from r2inspect.cli import interactive


class MockInspector:
    def __init__(self) -> None:
        self._calls: list[str] = []

    def get_strings(self) -> list[str]:
        self._calls.append("strings")
        return ["test_string"]

    def get_file_info(self) -> dict[str, object]:
        self._calls.append("info")
        return {"file": "test.exe"}

    def get_pe_info(self) -> dict[str, object]:
        self._calls.append("pe")
        return {"format": "PE32"}

    def get_imports(self) -> list[str]:
        self._calls.append("imports")
        return ["kernel32.dll"]

    def get_exports(self) -> list[str]:
        self._calls.append("exports")
        return ["export1"]

    def get_sections(self) -> list[dict[str, object]]:
        self._calls.append("sections")
        return [{"name": ".text"}]


def test_interactive_mode_exit_command() -> None:
    """Test interactive mode with 'exit' command"""
    inspector = MockInspector()
    options = {}

    stdin = io.StringIO("exit\n")
    original_stdin = sys.stdin
    try:
        sys.stdin = stdin
        interactive.run_interactive_mode(inspector, options)
    finally:
        sys.stdin = original_stdin


def test_interactive_mode_keyboard_interrupt() -> None:
    """Test interactive mode with KeyboardInterrupt"""
    inspector = MockInspector()
    options = {}

    call_count = [0]

    def mock_input(_prompt: str) -> str:
        call_count[0] += 1
        if call_count[0] == 1:
            raise KeyboardInterrupt()
        return "quit"

    interactive.run_interactive_mode(inspector, options, input_fn=mock_input)


def test_interactive_mode_eof_error() -> None:
    """Test interactive mode with EOFError"""
    inspector = MockInspector()
    options = {}

    call_count = [0]

    def mock_input(_prompt: str) -> str:
        call_count[0] += 1
        if call_count[0] == 1:
            raise EOFError()
        return "quit"

    interactive.run_interactive_mode(inspector, options, input_fn=mock_input)


def test_interactive_mode_empty_input() -> None:
    """Test interactive mode with empty input"""
    inspector = MockInspector()
    options = {}

    commands = "\n\nquit\n"
    stdin = io.StringIO(commands)
    original_stdin = sys.stdin
    try:
        sys.stdin = stdin
        interactive.run_interactive_mode(inspector, options)
    finally:
        sys.stdin = original_stdin


def test_interactive_mode_unknown_command() -> None:
    """Test interactive mode with unknown command"""
    inspector = MockInspector()
    options = {}

    commands = "invalid_command\nquit\n"
    stdin = io.StringIO(commands)
    original_stdin = sys.stdin
    try:
        sys.stdin = stdin
        interactive.run_interactive_mode(inspector, options)
    finally:
        sys.stdin = original_stdin
