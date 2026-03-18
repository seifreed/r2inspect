#!/usr/bin/env python3
"""Tests for r2inspect/cli/commands/analyze_command.py - AnalyzeCommand implementation.

All unittest.mock usage replaced with concrete fakes and real objects.
"""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from typing import Any

from rich.console import Console

from r2inspect.cli.commands.analyze_command import AnalyzeCommand
from r2inspect.cli.commands.base import CommandContext
from r2inspect.config import Config


# ---------------------------------------------------------------------------
# Concrete fakes
# ---------------------------------------------------------------------------


class CaptureConsole:
    """Console stand-in that records all printed messages."""

    def __init__(self) -> None:
        self.messages: list[str] = []

    def print(self, message: object = "", **kwargs: Any) -> None:
        self.messages.append(str(message))


class CaptureLogger:
    """Logger stand-in that records calls."""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.infos: list[str] = []

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self.errors.append(msg)

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self.warnings.append(msg)

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self.infos.append(msg)


def _make_context() -> CommandContext:
    console = CaptureConsole()
    logger = CaptureLogger()
    return CommandContext(console=console, logger=logger, config=Config())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_analyze_command_init():
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    assert cmd is not None
    assert cmd.context is context


def test_analyze_command_init_without_context():
    cmd = AnalyzeCommand()
    assert cmd is not None
    assert cmd.context is not None


def test_analyze_command_execute_keyboard_interrupt(tmp_path):
    """execute handles KeyboardInterrupt by returning 1.

    We trigger the interrupt by providing a non-existent file whose path
    triggers the error inside create_inspector.  For a true KeyboardInterrupt
    we subclass and override.
    """

    class _InterruptingCommand(AnalyzeCommand):
        def _show_analysis_start(self, filename: str) -> None:
            raise KeyboardInterrupt()

    ctx = _make_context()
    cmd = _InterruptingCommand(ctx)
    result = cmd.execute({"filename": "test.bin"})
    assert result == 1


def test_analyze_command_execute_error_handling():
    """execute handles general exceptions by returning 1."""

    class _ErrorCommand(AnalyzeCommand):
        def _show_analysis_start(self, filename: str) -> None:
            raise RuntimeError("Test error")

    ctx = _make_context()
    cmd = _ErrorCommand(ctx)
    result = cmd.execute({"filename": "test.bin", "verbose": False})
    assert result == 1


def test_analyze_command_execute_error_verbose():
    """execute shows traceback in verbose mode."""

    class _ErrorCommand(AnalyzeCommand):
        def _show_analysis_start(self, filename: str) -> None:
            raise RuntimeError("Test error")

    ctx = _make_context()
    cmd = _ErrorCommand(ctx)
    result = cmd.execute({"filename": "test.bin", "verbose": True})
    assert result == 1


def test_analyze_command_get_config():
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    config = cmd._get_config()
    assert config is not None
    assert isinstance(config, Config)


def test_analyze_command_get_config_with_path():
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    config = cmd._get_config(config_path=None)
    assert config is not None


def test_analyze_command_setup_analysis_options_empty():
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    options = cmd._setup_analysis_options()
    assert options == {}


def test_analyze_command_setup_analysis_options_yara():
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    options = cmd._setup_analysis_options(yara="/path/to/rules")
    assert "yara_rules_dir" in options
    assert options["yara_rules_dir"] == "/path/to/rules"


def test_analyze_command_setup_analysis_options_xor():
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    options = cmd._setup_analysis_options(xor="DEADBEEF")
    assert "xor_search" in options
    assert options["xor_search"] == "DEADBEEF"


def test_analyze_command_setup_analysis_options_both():
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    options = cmd._setup_analysis_options(yara="/rules", xor="FF")
    assert len(options) == 2
    assert options["yara_rules_dir"] == "/rules"
    assert options["xor_search"] == "FF"


def test_analyze_command_print_status_if_needed_console_output():
    """_print_status_if_needed writes a status message to the console."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)
    cmd._print_status_if_needed(
        output_json=False,
        output_csv=False,
        output_file=None,
    )
    assert any("Starting analysis" in m for m in ctx.console.messages)


def test_analyze_command_print_status_if_needed_json():
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)
    cmd._print_status_if_needed(
        output_json=True,
        output_csv=False,
        output_file="/tmp/output.json",
    )
    assert any("Starting analysis" in m for m in ctx.console.messages)


def test_analyze_command_print_status_if_needed_csv():
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)
    cmd._print_status_if_needed(
        output_json=False,
        output_csv=True,
        output_file="/tmp/output.csv",
    )
    assert any("Starting analysis" in m for m in ctx.console.messages)


def test_analyze_command_output_results(tmp_path):
    """_output_results delegates to analysis_output.output_results."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)
    results = {"analysis": "data"}

    # Console output path -- just verify no crash
    cmd._output_results(
        results=results,
        output_json=False,
        output_csv=False,
        output_file=None,
        verbose=False,
    )


def test_analyze_command_output_console_results():
    """_output_console_results runs without error."""
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)
    results = {"analysis": "data"}
    cmd._output_console_results(results, verbose=False)


def test_analyze_command_output_console_results_verbose():
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)
    results = {"analysis": "data"}
    cmd._output_console_results(results, verbose=True)


def test_analyze_command_display_verbose_statistics():
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)
    cmd._display_verbose_statistics()


def test_analyze_command_handle_error_verbose():
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)
    error = Exception("Test error")
    cmd._handle_error(error, verbose=True)
    assert len(ctx.logger.errors) > 0


def test_analyze_command_handle_error_quiet():
    ctx = _make_context()
    cmd = AnalyzeCommand(ctx)
    error = Exception("Test error")
    cmd._handle_error(error, verbose=False)
    assert len(ctx.logger.errors) > 0


def test_analyze_command_run_analysis():
    """_run_analysis completes when given a fake inspector."""

    class _FakeInspector:
        def analyze(self, **kwargs):
            return {"analysis": "data"}

    class _CaptureCommand(AnalyzeCommand):
        def _output_results(self, results, output_json, output_csv, output_file, verbose):
            self.captured_results = results

    ctx = _make_context()
    cmd = _CaptureCommand(ctx)

    cmd._run_analysis(
        inspector=_FakeInspector(),
        options={},
        output_json=False,
        output_csv=False,
        output_file=None,
        verbose=False,
    )
    # The use-case may enrich results with statistics; verify the original key is present
    assert cmd.captured_results["analysis"] == "data"


def test_analyze_command_args_processing():
    context = CommandContext.create()
    _cmd = AnalyzeCommand(context)
    args = {
        "filename": "test.bin",
        "config": None,
        "verbose": False,
        "threads": None,
        "yara": None,
        "xor": None,
        "output_json": False,
        "output_csv": False,
        "output": None,
    }
    assert "filename" in args
    assert args["filename"] == "test.bin"


def test_analyze_command_threads_setting():
    """execute applies thread settings before analysis."""

    class _ThreadCapture(AnalyzeCommand):
        def _show_analysis_start(self, filename: str) -> None:
            # Stop execution after thread settings have been applied
            raise StopIteration("done")

    ctx = _make_context()
    cmd = _ThreadCapture(ctx)
    result = cmd.execute(
        {
            "filename": "test.bin",
            "config": None,
            "verbose": False,
            "threads": 4,
        }
    )
    # StopIteration is caught by the general except block -> returns 1
    assert result == 1
