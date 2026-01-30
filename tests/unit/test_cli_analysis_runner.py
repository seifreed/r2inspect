import json
from pathlib import Path

from r2inspect.cli.analysis_runner import (
    add_statistics_to_results,
    has_circuit_breaker_data,
    output_csv_results,
    output_json_results,
    setup_analysis_options,
    setup_single_file_output,
)
from r2inspect.utils.output import OutputFormatter


def test_setup_single_file_output(tmp_path):
    output = setup_single_file_output(True, False, None, str(tmp_path / "sample.exe"))
    assert str(output).endswith("_analysis.json")


def test_setup_analysis_options():
    options = setup_analysis_options("rules", "xor")
    assert options["detect_packer"] is True
    assert options["custom_yara"] == "rules"


def test_has_circuit_breaker_data():
    assert has_circuit_breaker_data({"a": 0}) is False
    assert has_circuit_breaker_data({"a": 1}) is True


def test_output_json_and_csv_results(tmp_path):
    results = {"file_info": {"name": "sample", "size": 1}}
    formatter = OutputFormatter(results)

    json_path = tmp_path / "out.json"
    output_json_results(formatter, str(json_path))
    loaded = json.loads(json_path.read_text())
    assert loaded["file_info"]["name"] == "sample"

    csv_path = tmp_path / "out.csv"
    output_csv_results(formatter, str(csv_path))
    assert csv_path.read_text().startswith("name,size")


def test_add_statistics_to_results():
    results = {}
    add_statistics_to_results(results)
    # error/retry stats may or may not be present, but should not error
    assert isinstance(results, dict)
