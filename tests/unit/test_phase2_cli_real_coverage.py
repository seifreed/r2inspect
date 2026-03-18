from __future__ import annotations

import io
import sys
from pathlib import Path
from typing import Any

from rich.console import Console

from r2inspect.application.use_cases import AnalyzeBinaryUseCase
from r2inspect.cli.commands.base import CommandContext
from r2inspect.cli.commands.config_command import ConfigCommand
from r2inspect.cli.commands.interactive_command import InteractiveCommand
from r2inspect.config import Config
from r2inspect.infrastructure.logging import get_logger
from tests.helpers import run_cli


class _Inspector:
    def analyze(self, **_kwargs: Any) -> dict[str, Any]:
        return {"file_info": {"name": "sample.bin", "size": 10}}

    def get_strings(self) -> list[str]:
        return ["alpha", "beta"]

    def get_file_info(self) -> dict[str, Any]:
        return {"name": "sample.bin", "size": 10}

    def get_pe_info(self) -> dict[str, Any]:
        return {"compile_time": "now"}

    def get_imports(self) -> list[str]:
        return ["kernel32.dll"]

    def get_exports(self) -> list[str]:
        return ["ExportedFunc"]

    def get_sections(self) -> list[dict[str, Any]]:
        return [{"name": ".text", "size": 100}]


class _FakeResult:
    """Fake result with to_dict() for CLI boundary compatibility."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def to_dict(self) -> dict[str, Any]:
        return self._data


class _UseCase:
    def run(self, inspector: Any, options: dict[str, Any], **_kwargs: Any) -> _FakeResult:
        return _FakeResult(
            {
                "file_info": inspector.get_file_info(),
                "options": options,
            }
        )


class _InteractiveCommandForTest(InteractiveCommand):
    def _analyze_binary_use_case(self) -> Any:
        return _UseCase()


def _make_console() -> Console:
    return Console(file=io.StringIO(), force_terminal=False, width=120)


def _make_context(tmp_path: Path, *, verbose: bool = False) -> CommandContext:
    return CommandContext(
        console=_make_console(),
        logger=get_logger(),
        config=Config(str(tmp_path / "config.json")),
        verbose=verbose,
        quiet=False,
    )


def test_config_command_execute_and_empty_rules_directory_real(tmp_path: Path) -> None:
    context = _make_context(tmp_path)
    command = ConfigCommand(context)

    assert command.execute({}) == 0
    assert "No configuration operation specified" in context.console.file.getvalue()

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    status = command.execute({"list_yara": True, "yara": str(rules_dir), "config": None})
    assert status == 0
    assert "No YARA rules found in" in context.console.file.getvalue()


def test_config_command_size_format_and_cli_list_yara_real(tmp_path: Path) -> None:
    command = ConfigCommand(_make_context(tmp_path))
    assert command._format_file_size(1024 * 1024 * 1024) == "1.0 GB"

    rules_dir = tmp_path / "rules"
    (rules_dir / "sub").mkdir(parents=True)
    (rules_dir / "one.yar").write_text("rule one { condition: true }")
    (rules_dir / "sub" / "two.yara").write_text("rule two { condition: true }")

    result = run_cli(["--list-yara", "--yara", str(rules_dir)])
    assert result.returncode == 0
    assert "Available YARA Rules" in result.stdout
    assert "sub/two.yara" in result.stdout


def test_config_command_relative_display_name_fallback_real(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    outside_rule = tmp_path / "outside.yar"
    outside_rule.write_text("rule outside { condition: true }")

    context = _make_context(tmp_path)
    command = ConfigCommand(context)
    command._display_yara_rules_table([outside_rule], rules_dir)

    assert "outside.yar" in context.console.file.getvalue()


def test_interactive_command_wrappers_and_error_rendering_real(tmp_path: Path) -> None:
    context = _make_context(tmp_path)
    command = _InteractiveCommandForTest(context)
    inspector = _Inspector()
    observed: list[dict[str, Any]] = []

    command._display_welcome()
    command._cmd_strings(inspector)
    command._cmd_info(inspector)
    command._cmd_pe(inspector)
    command._cmd_imports(inspector)
    command._cmd_exports(inspector)
    command._cmd_sections(inspector)
    command._cmd_analyze(inspector, {"xor_search": "aa"}, observed.append)
    command._execute_interactive_command("unknown", inspector, {})
    command._handle_error(RuntimeError("boom"), verbose=False)

    text = context.console.file.getvalue()
    assert "Interactive Mode - r2inspect" in text
    assert "alpha" in text
    assert "File Information" in text
    assert "PE Information" in text
    assert "kernel32.dll" in text
    assert "ExportedFunc" in text
    assert "Unknown command" in text
    assert "Analysis failed: boom" in text
    assert observed == [
        {"file_info": {"name": "sample.bin", "size": 10}, "options": {"xor_search": "aa"}}
    ]


def test_interactive_command_run_loop_real_stdin_paths(tmp_path: Path) -> None:
    context = _make_context(tmp_path)
    command = _InteractiveCommandForTest(context)
    inspector = _Inspector()
    original_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO("help\n\nquit\n")
        command._run_interactive_mode(inspector, {})
    finally:
        sys.stdin = original_stdin

    output = context.console.file.getvalue()
    assert "Interactive Mode - r2inspect" in output
    assert "Exiting interactive mode" in output


def test_interactive_command_run_loop_eof_and_command_error_real(tmp_path: Path) -> None:
    class _ExplodingInteractive(_InteractiveCommandForTest):
        def _execute_interactive_command(
            self, cmd: str, inspector: Any, options: dict[str, Any]
        ) -> None:
            raise RuntimeError(f"bad command: {cmd}")

    eof_context = _make_context(tmp_path)
    eof_command = _InteractiveCommandForTest(eof_context)
    original_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO("")
        eof_command._run_interactive_mode(_Inspector(), {})
    finally:
        sys.stdin = original_stdin
    assert "Exiting interactive mode" in eof_context.console.file.getvalue()

    error_context = _make_context(tmp_path)
    error_command = _ExplodingInteractive(error_context)
    try:
        sys.stdin = io.StringIO("broken\nquit\n")
        error_command._run_interactive_mode(_Inspector(), {})
    finally:
        sys.stdin = original_stdin
    assert "Command error: bad command: broken" in error_context.console.file.getvalue()


def test_interactive_command_verbose_error_and_execute_failure_real(tmp_path: Path) -> None:
    verbose_context = _make_context(tmp_path, verbose=True)
    command = _InteractiveCommandForTest(verbose_context)
    command._handle_error(RuntimeError("verbose boom"), verbose=True)
    verbose_output = verbose_context.console.file.getvalue()
    assert "Error: verbose boom" in verbose_output
    assert "NoneType: None" in verbose_output

    failing_command = InteractiveCommand(_make_context(tmp_path, verbose=False))
    code = failing_command.execute(
        {
            "filename": "no_such_file.bin",
            "config": None,
            "yara": None,
            "xor": None,
            "verbose": False,
        }
    )
    output = failing_command.context.console.file.getvalue()
    assert code == 1
    assert "Interactive mode failed" in output


def test_interactive_command_execute_success_and_keyboard_interrupt_real(tmp_path: Path) -> None:
    context = _make_context(tmp_path)
    command = InteractiveCommand(context)
    original_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO("quit\n")
        code = command.execute(
            {
                "filename": "samples/fixtures/hello_pe.exe",
                "config": None,
                "yara": None,
                "xor": None,
                "verbose": False,
            }
        )
    finally:
        sys.stdin = original_stdin

    assert code == 0
    assert (
        "Initializing analysis for: samples/fixtures/hello_pe.exe"
        in context.console.file.getvalue()
    )
    assert isinstance(command._analyze_binary_use_case(), AnalyzeBinaryUseCase)

    class _KeyboardInterruptInteractive(InteractiveCommand):
        def _run_interactive_mode(self, inspector: Any, options: dict[str, Any]) -> None:
            raise KeyboardInterrupt

    interrupted = _KeyboardInterruptInteractive(_make_context(tmp_path))
    code = interrupted.execute(
        {
            "filename": "samples/fixtures/hello_pe.exe",
            "config": None,
            "yara": None,
            "xor": None,
            "verbose": False,
        }
    )
    assert code == 0
    assert "interrupted by user" in interrupted.context.console.file.getvalue().lower()


def test_interactive_command_real_repl_via_cli_runner() -> None:
    result = run_cli(
        ["--interactive", "samples/fixtures/hello_pe.exe"],
        input_text="help\n\nquit\n",
    )
    assert result.returncode == 0
    assert "Interactive Mode - r2inspect" in result.stdout
    assert "Exiting interactive mode" in result.stdout
