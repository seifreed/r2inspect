from __future__ import annotations

from pathlib import Path

from r2inspect.cli.analysis_runner import (
    has_circuit_breaker_data,
    output_csv_results,
    output_json_results,
    print_status_if_appropriate,
    setup_analysis_options,
    setup_single_file_output,
)
from r2inspect.utils.output import OutputFormatter


def test_setup_single_file_output(tmp_path: Path):
    filename = tmp_path / "sample.bin"
    filename.write_bytes(b"data")

    out = setup_single_file_output(True, False, None, str(filename))
    assert str(out).endswith("sample_analysis.json")

    out = setup_single_file_output(False, True, None, str(filename))
    assert str(out).endswith("sample_analysis.csv")


def test_setup_analysis_options():
    opts = setup_analysis_options("rules", "AA")
    assert opts["detect_packer"] is True
    assert opts["custom_yara"] == "rules"
    assert opts["xor_search"] == "AA"


def test_output_json_and_csv_results(tmp_path: Path, capsys):
    results = {"file_info": {"name": "sample"}}
    formatter = OutputFormatter(results)

    json_file = tmp_path / "out.json"
    output_json_results(formatter, str(json_file))
    assert json_file.exists()
    assert "JSON results saved" in capsys.readouterr().out

    csv_file = tmp_path / "out.csv"
    output_csv_results(formatter, str(csv_file))
    assert csv_file.exists()
    assert "CSV results saved" in capsys.readouterr().out


def test_print_status_and_circuit_stats(capsys):
    print_status_if_appropriate(False, False, None)
    assert "Starting analysis" in capsys.readouterr().out

    assert has_circuit_breaker_data({}) is False
    assert has_circuit_breaker_data({"failures": 0}) is False
    assert has_circuit_breaker_data({"failures": 2}) is True
