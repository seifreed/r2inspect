from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


def test_interactive_command_execute():
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")

    script = r"""
from r2inspect.cli.commands.interactive_command import InteractiveCommand
from r2inspect.cli.commands.base import CommandContext

cmd = InteractiveCommand(CommandContext.create())
exit_code = cmd.execute({
    "filename": "samples/fixtures/hello_pe.exe",
    "config": None,
    "yara": None,
    "xor": None,
    "verbose": False,
})
print("EXIT", exit_code)
"""
    proc = subprocess.run(
        [sys.executable, "-c", script],
        input="help\nquit\n",
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert "Interactive Mode" in proc.stdout
    assert "EXIT 0" in proc.stdout
