from __future__ import annotations

import io
import signal
import sys
import threading
from pathlib import Path

import pytest

from r2inspect.cli.commands.base import Command, CommandContext, configure_quiet_logging
from r2inspect.cli.commands.interactive_command import InteractiveCommand
from r2inspect.config import Config


class _DummyCommand(Command):
    def execute(self, args: dict[str, object]) -> int:
        return 0


def _sample_path() -> Path:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")
    return sample


@pytest.mark.unit
def test_configure_quiet_logging_noop_when_false() -> None:
    configure_quiet_logging(False)


@pytest.mark.unit
def test_command_get_config_uses_default_when_context_missing() -> None:
    cmd = _DummyCommand()
    cmd.context = CommandContext.create(config=None)
    cmd.context.config = None
    cfg = cmd._get_config()
    assert isinstance(cfg, Config)


@pytest.mark.unit
def test_interactive_command_execute_handles_invalid_file_non_verbose() -> None:
    cmd = InteractiveCommand(CommandContext.create(quiet=True))
    buffer = io.StringIO()
    original_file = cmd.context.console.file
    try:
        cmd.context.console.file = buffer
        exit_code = cmd.execute(
            {
                "filename": "does_not_exist.bin",
                "config": None,
                "yara": None,
                "xor": None,
                "verbose": False,
            }
        )
    finally:
        cmd.context.console.file = original_file

    assert exit_code == 1
    out = buffer.getvalue()
    assert "Interactive mode failed" in out


@pytest.mark.unit
def test_interactive_command_execute_handles_invalid_file_verbose() -> None:
    cmd = InteractiveCommand(CommandContext.create(quiet=True))
    buffer = io.StringIO()
    original_file = cmd.context.console.file
    try:
        cmd.context.console.file = buffer
        exit_code = cmd.execute(
            {
                "filename": "does_not_exist.bin",
                "config": None,
                "yara": None,
                "xor": None,
                "verbose": True,
            }
        )
    finally:
        cmd.context.console.file = original_file

    assert exit_code == 1
    out = buffer.getvalue()
    assert "Error:" in out


@pytest.mark.unit
def test_interactive_command_execute_keyboard_interrupt() -> None:
    sample = _sample_path()
    cmd = InteractiveCommand(CommandContext.create(quiet=True))
    original_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO("help\n")
        threading.Timer(0.05, lambda: signal.raise_signal(signal.SIGINT)).start()
        exit_code = cmd.execute(
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

    assert exit_code == 0
