from __future__ import annotations

import os
from pathlib import Path

import pytest

from r2inspect.cli.analysis_runner import (
    handle_main_error,
    output_csv_results,
    output_json_results,
    setup_analysis_options,
    setup_single_file_output,
)
from r2inspect.utils.output import OutputFormatter


def test_setup_analysis_options_defaults():
    options = setup_analysis_options("/tmp/yara", "abcd")
    assert options["detect_packer"] is True
    assert options["detect_crypto"] is True
    assert options["detect_av"] is True
    assert options["full_analysis"] is True
    assert options["custom_yara"] == "/tmp/yara"
    assert options["xor_search"] == "abcd"


def test_setup_single_file_output_creates_paths(tmp_path):
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        output = setup_single_file_output(True, False, None, "sample.bin")
        assert output is not None
        assert Path(output).parent.name == "output"
        assert str(output).endswith("sample_analysis.json")

        output_csv = setup_single_file_output(False, True, None, "sample.bin")
        assert output_csv is not None
        assert str(output_csv).endswith("sample_analysis.csv")
    finally:
        os.chdir(cwd)


def test_output_json_results_writes_file(tmp_path):
    formatter = OutputFormatter({"file_info": {"name": "sample"}})
    out_file = tmp_path / "results.json"
    output_json_results(formatter, str(out_file))
    assert out_file.exists()
    assert "sample" in out_file.read_text()


def test_output_csv_results_writes_file(tmp_path):
    formatter = OutputFormatter({"file_info": {"name": "sample", "size": 1}})
    out_file = tmp_path / "results.csv"
    output_csv_results(formatter, str(out_file))
    assert out_file.exists()
    text = out_file.read_text()
    assert "name" in text
    assert "sample" in text


def test_handle_main_error_exits():
    with pytest.raises(SystemExit) as exc:
        handle_main_error(RuntimeError("boom"), verbose=False)
    assert exc.value.code == 1
