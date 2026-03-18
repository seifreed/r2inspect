#!/usr/bin/env python3
"""
Comprehensive tests for r2inspect/cli/commands/batch_command.py module.
Tests batch command execution, error handling, and configuration.
Coverage target: 100% (currently 16%)

All unittest.mock usage replaced with concrete fakes.
"""

import logging
from io import StringIO
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from r2inspect.cli.commands.batch_command import BatchCommand
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
    """Logger stand-in that records calls by level."""

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
    """Build a CommandContext wired to capture fakes."""
    console = CaptureConsole()
    logger = CaptureLogger()
    return CommandContext(console=console, logger=logger, config=Config())


def _make_batch_command() -> BatchCommand:
    cmd = BatchCommand()
    cmd.context = _make_context()
    return cmd


# ---------------------------------------------------------------------------
# Subclass that intercepts _run_batch_analysis
# ---------------------------------------------------------------------------


class _NoOpBatchCommand(BatchCommand):
    """BatchCommand that skips the heavy batch runner."""

    def __init__(self, *, raise_on_run: Exception | None = None) -> None:
        super().__init__()
        self._raise_on_run = raise_on_run
        self.run_batch_called = False
        self.run_batch_kwargs: dict[str, Any] = {}

    def _run_batch_analysis(self, **kwargs: Any) -> None:
        self.run_batch_called = True
        self.run_batch_kwargs = kwargs
        if self._raise_on_run is not None:
            raise self._raise_on_run


@pytest.fixture
def sample_batch_dir(tmp_path):
    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()
    (batch_dir / "file1.exe").write_bytes(b"MZ" + b"\x00" * 100)
    (batch_dir / "file2.dll").write_bytes(b"MZ" + b"\x00" * 100)
    return batch_dir


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_batch_command_initialization():
    command = BatchCommand()
    assert command is not None


def test_execute_basic_success(sample_batch_dir):
    cmd = _NoOpBatchCommand()
    cmd.context = _make_context()
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "yara": None,
        "xor": None,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1,
        "verbose": False,
        "quiet": True,
    }
    result = cmd.execute(args)
    assert result == 0
    assert cmd.run_batch_called is True


def test_execute_with_json_output(sample_batch_dir):
    cmd = _NoOpBatchCommand()
    cmd.context = _make_context()
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "output_json": True,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1,
        "verbose": False,
        "quiet": True,
    }
    result = cmd.execute(args)
    assert result == 0


def test_execute_with_csv_output(sample_batch_dir):
    cmd = _NoOpBatchCommand()
    cmd.context = _make_context()
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "output_json": False,
        "output_csv": True,
        "output": None,
        "extensions": None,
        "threads": 1,
        "verbose": False,
        "quiet": True,
    }
    result = cmd.execute(args)
    assert result == 0


def test_execute_with_both_outputs(sample_batch_dir):
    cmd = _NoOpBatchCommand()
    cmd.context = _make_context()
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "output_json": True,
        "output_csv": True,
        "output": None,
        "extensions": None,
        "threads": 1,
        "verbose": False,
        "quiet": True,
    }
    result = cmd.execute(args)
    assert result == 0


def test_execute_with_extensions(sample_batch_dir):
    cmd = _NoOpBatchCommand()
    cmd.context = _make_context()
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "extensions": "exe,dll",
        "output_json": False,
        "output_csv": False,
        "output": None,
        "threads": 1,
        "verbose": False,
        "quiet": True,
    }
    result = cmd.execute(args)
    assert result == 0


def test_execute_with_yara(sample_batch_dir, tmp_path):
    yara_dir = tmp_path / "yara"
    yara_dir.mkdir()
    cmd = _NoOpBatchCommand()
    cmd.context = _make_context()
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "yara": str(yara_dir),
        "xor": None,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1,
        "verbose": False,
        "quiet": True,
    }
    result = cmd.execute(args)
    assert result == 0


def test_execute_with_xor(sample_batch_dir):
    cmd = _NoOpBatchCommand()
    cmd.context = _make_context()
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "yara": None,
        "xor": "test_string",
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1,
        "verbose": False,
        "quiet": True,
    }
    result = cmd.execute(args)
    assert result == 0


def test_execute_with_verbose(sample_batch_dir):
    cmd = _NoOpBatchCommand()
    cmd.context = _make_context()
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "verbose": True,
        "quiet": False,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1,
    }
    result = cmd.execute(args)
    assert result == 0


def test_execute_with_multiple_threads(sample_batch_dir):
    cmd = _NoOpBatchCommand()
    cmd.context = _make_context()
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "threads": 4,
        "verbose": False,
        "quiet": True,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None,
    }
    result = cmd.execute(args)
    assert result == 0


def test_execute_keyboard_interrupt(sample_batch_dir):
    cmd = _NoOpBatchCommand(raise_on_run=KeyboardInterrupt())
    cmd.context = _make_context()
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "verbose": False,
        "quiet": True,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1,
    }
    result = cmd.execute(args)
    assert result == 1
    assert any("interrupted" in m.lower() for m in cmd.context.console.messages)


def test_execute_exception_verbose(sample_batch_dir):
    cmd = _NoOpBatchCommand(raise_on_run=ValueError("Test error"))
    cmd.context = _make_context()
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "verbose": True,
        "quiet": False,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1,
    }
    result = cmd.execute(args)
    assert result == 1
    assert len(cmd.context.logger.errors) > 0


def test_execute_exception_normal(sample_batch_dir):
    cmd = _NoOpBatchCommand(raise_on_run=RuntimeError("Test error"))
    cmd.context = _make_context()
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "verbose": False,
        "quiet": True,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1,
    }
    result = cmd.execute(args)
    assert result == 1


def test_setup_batch_mode_default():
    command = BatchCommand()
    recursive, auto_detect, output_dir = command._setup_batch_mode(
        _batch="/path/to/batch",
        extensions=None,
        output_json=False,
        output_csv=False,
        output=None,
    )
    assert recursive is True
    assert auto_detect is True
    assert output_dir is None


def test_setup_batch_mode_with_extensions():
    command = BatchCommand()
    recursive, auto_detect, output_dir = command._setup_batch_mode(
        _batch="/path/to/batch",
        extensions="exe,dll",
        output_json=False,
        output_csv=False,
        output=None,
    )
    assert recursive is True
    assert auto_detect is False
    assert output_dir is None


def test_setup_batch_mode_json_output():
    command = BatchCommand()
    recursive, auto_detect, output_dir = command._setup_batch_mode(
        _batch="/path/to/batch",
        extensions=None,
        output_json=True,
        output_csv=False,
        output=None,
    )
    assert recursive is True
    assert auto_detect is True
    assert output_dir == "output"


def test_setup_batch_mode_csv_output():
    command = BatchCommand()
    recursive, auto_detect, output_dir = command._setup_batch_mode(
        _batch="/path/to/batch",
        extensions=None,
        output_json=False,
        output_csv=True,
        output=None,
    )
    assert recursive is True
    assert auto_detect is True
    assert output_dir == "output"


def test_setup_batch_mode_custom_output():
    command = BatchCommand()
    recursive, auto_detect, output_dir = command._setup_batch_mode(
        _batch="/path/to/batch",
        extensions=None,
        output_json=True,
        output_csv=True,
        output="/custom/output",
    )
    assert output_dir == "/custom/output"


def test_setup_analysis_options_default():
    command = BatchCommand()
    options = command._setup_analysis_options()
    assert options["detect_packer"] is True
    assert options["detect_crypto"] is True
    assert options["detect_av"] is True
    assert options["full_analysis"] is True


def test_setup_analysis_options_with_yara():
    command = BatchCommand()
    options = command._setup_analysis_options(yara="/path/to/yara")
    assert options["custom_yara"] == "/path/to/yara"


def test_setup_analysis_options_with_xor():
    command = BatchCommand()
    options = command._setup_analysis_options(xor="test_xor")
    assert options["xor_search"] == "test_xor"


def test_setup_analysis_options_with_both():
    command = BatchCommand()
    options = command._setup_analysis_options(yara="/path/to/yara", xor="test_xor")
    assert options["custom_yara"] == "/path/to/yara"
    assert options["xor_search"] == "test_xor"


def test_configure_batch_logging_verbose():
    command = BatchCommand()
    command._configure_batch_logging(verbose=True, quiet=False)


def test_configure_batch_logging_quiet():
    command = BatchCommand()
    command._configure_batch_logging(verbose=False, quiet=True)
    logger = logging.getLogger("r2inspect")
    assert logger.level == logging.CRITICAL


def test_configure_batch_logging_normal():
    command = BatchCommand()
    command._configure_batch_logging(verbose=False, quiet=False)


def test_handle_error_verbose():
    cmd = _make_batch_command()
    error = ValueError("Test error message")
    cmd._handle_error(error, verbose=True)
    assert len(cmd.context.logger.errors) > 0
    assert any("Test error" in m for m in cmd.context.console.messages)


def test_handle_error_normal():
    cmd = _make_batch_command()
    error = RuntimeError("Test error message")
    cmd._handle_error(error, verbose=False)
    assert len(cmd.context.logger.errors) > 0
    assert any("Test error" in m for m in cmd.context.console.messages)


def test_execute_with_config_file(sample_batch_dir, tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text('{"key": "value"}')
    cmd = _NoOpBatchCommand()
    cmd.context = _make_context()
    args = {
        "batch": str(sample_batch_dir),
        "config": str(config_file),
        "verbose": False,
        "quiet": True,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1,
    }
    result = cmd.execute(args)
    assert result == 0


def test_execute_full_workflow(sample_batch_dir, tmp_path):
    output_dir = tmp_path / "output"
    cmd = _NoOpBatchCommand()
    cmd.context = _make_context()
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "yara": None,
        "xor": "test_xor",
        "output_json": True,
        "output_csv": True,
        "output": str(output_dir),
        "extensions": "exe,dll",
        "threads": 2,
        "verbose": True,
        "quiet": False,
    }
    result = cmd.execute(args)
    assert result == 0
