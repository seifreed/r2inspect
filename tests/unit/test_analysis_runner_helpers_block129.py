from __future__ import annotations

from pathlib import Path

from r2inspect.cli.analysis_runner import (
    output_csv_results,
    output_json_results,
    setup_analysis_options,
    setup_single_file_output,
)
from r2inspect.utils.output import OutputFormatter


def test_setup_single_file_output_creates_default_path(tmp_path: Path):
    input_file = tmp_path / "sample.bin"
    input_file.write_text("data")

    output = setup_single_file_output(True, False, None, str(input_file))
    assert output is not None
    assert str(output).endswith("sample_analysis.json")
    assert Path("output").exists()


def test_output_json_and_csv_results(tmp_path: Path):
    results = {"name": "sample", "size": 123}
    formatter = OutputFormatter(results)

    json_path = tmp_path / "out.json"
    csv_path = tmp_path / "out.csv"

    output_json_results(formatter, str(json_path))
    output_csv_results(formatter, str(csv_path))

    assert json_path.exists()
    assert csv_path.exists()


def test_setup_analysis_options_contains_defaults():
    options = setup_analysis_options("/rules", "aa")
    assert options["detect_packer"] is True
    assert options["custom_yara"] == "/rules"
    assert options["xor_search"] == "aa"
