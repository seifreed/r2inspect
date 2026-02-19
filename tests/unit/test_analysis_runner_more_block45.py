from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from rich.console import Console

from r2inspect.cli import display as display_module
from r2inspect.cli import display_base
from r2inspect.cli.analysis_runner import (
    output_console_results,
    output_csv_results,
    output_json_results,
)
from r2inspect.utils.output import OutputFormatter


def test_output_console_results_verbose() -> None:
    results = {"file_info": {"name": "sample"}}
    buffer = io.StringIO()
    original_console = display_base.console
    original_display_console = display_module.console
    try:
        console = Console(file=buffer, force_terminal=False, color_system=None)
        display_base.console = console
        display_module.console = console
        output_console_results(results, verbose=False)
        out = buffer.getvalue()
        assert "sample" in out
    finally:
        display_base.console = original_console
        display_module.console = original_display_console


def test_output_json_csv_stdout(capsys):
    formatter = OutputFormatter({"file_info": {"name": "sample"}})
    output_json_results(formatter, None)
    output_csv_results(formatter, None)
    out = capsys.readouterr().out
    assert "file_info" in out or "sample" in out
