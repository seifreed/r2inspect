"""Canonical import tests for CLI output formatters."""

from r2inspect.cli.output_csv import CsvOutputFormatter
from r2inspect.cli.output_formatters import OutputFormatter


def test_cli_output_formatter_exports_work() -> None:
    formatter = OutputFormatter({"file_info": {"name": "sample.bin", "size": 3}})

    assert "sample.bin" in formatter.to_json()
    assert "name" in formatter.to_csv().lower()


def test_csv_delimiter_default_is_comma() -> None:
    csv_text = CsvOutputFormatter({"file_info": {"name": "s.bin", "size": 3}}).to_csv()
    header = csv_text.splitlines()[0]
    assert header.startswith("name,size,")
    assert ";" not in header


def test_csv_delimiter_applies_configured_delimiter() -> None:
    results = {"file_info": {"name": "s.bin", "size": 3}}
    header = CsvOutputFormatter(results, delimiter=";").to_csv().splitlines()[0]
    assert header.startswith("name;size;")
    # OutputFormatter threads the delimiter through to the CSV formatter.
    of_header = OutputFormatter(results, csv_delimiter=";").to_csv().splitlines()[0]
    assert of_header.startswith("name;size;")
