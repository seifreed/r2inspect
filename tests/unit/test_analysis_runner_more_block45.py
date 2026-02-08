from __future__ import annotations

import json
from pathlib import Path

import pytest

from r2inspect.cli.analysis_runner import (
    output_console_results,
    output_csv_results,
    output_json_results,
)
from r2inspect.utils.output import OutputFormatter


def test_output_console_results_verbose(capsys):
    results = {"file_info": {"name": "sample"}}
    output_console_results(results, verbose=False)
    out = capsys.readouterr().out
    assert "sample" in out


def test_output_json_csv_stdout(capsys):
    formatter = OutputFormatter({"file_info": {"name": "sample"}})
    output_json_results(formatter, None)
    output_csv_results(formatter, None)
    out = capsys.readouterr().out
    assert "file_info" in out or "sample" in out
