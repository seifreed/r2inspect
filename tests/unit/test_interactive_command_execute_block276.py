from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from r2inspect.cli.commands import CommandContext
from r2inspect.cli.commands.interactive_command import InteractiveCommand


@pytest.mark.unit
def test_interactive_command_execute_quick_exit() -> None:
    context = CommandContext.create(quiet=True)
    cmd = InteractiveCommand(context)

    fixture = Path("samples/fixtures/hello_pe.exe")
    assert fixture.exists()

    original_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO("quit\n")
        exit_code = cmd.execute(
            {
                "filename": str(fixture),
                "config": None,
                "yara": None,
                "xor": None,
                "verbose": False,
            }
        )
    finally:
        sys.stdin = original_stdin

    assert exit_code == 0
