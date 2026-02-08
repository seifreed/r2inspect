from __future__ import annotations

import io
import subprocess
import sys
from pathlib import Path

import pytest

from r2inspect.cli import interactive
from r2inspect.factory import create_inspector
from r2inspect.utils.output import OutputFormatter


def test_show_strings_only(tmp_path: Path, capsys):
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")
    with create_inspector(str(sample)) as inspector:
        buffer = io.StringIO()
        original_file = interactive.console.file
        try:
            interactive.console.file = buffer
            interactive.show_strings_only(inspector)
        finally:
            interactive.console.file = original_file
    out = buffer.getvalue()
    assert "Extracting strings" in out


def test_show_info_table(capsys):
    formatter = OutputFormatter({"file_info": {"arch": "x86"}})
    buffer = io.StringIO()
    original_file = interactive.console.file
    try:
        interactive.console.file = buffer
        interactive._show_info_table("File Information", {"arch": "x86"}, formatter)
    finally:
        interactive.console.file = original_file
    out = buffer.getvalue()
    assert "File Information" in out


def test_run_interactive_mode_strings_only():
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")

    script = r"""
from r2inspect.cli.interactive import run_interactive_mode
from r2inspect.factory import create_inspector

inspector = create_inspector("samples/fixtures/hello_pe.exe")
run_interactive_mode(inspector, {})
inspector.close()
"""
    proc = subprocess.run(
        [sys.executable, "-c", script],
        input="strings\nquit\n",
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert "Interactive Mode" in proc.stdout
