from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


def test_interactive_mode_basic():
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")

    script = r"""
from r2inspect.factory import create_inspector
from r2inspect.cli.interactive import run_interactive_mode

inspector = create_inspector("samples/fixtures/hello_pe.exe")
run_interactive_mode(inspector, {})
inspector.close()
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
    assert "Available commands" in proc.stdout
