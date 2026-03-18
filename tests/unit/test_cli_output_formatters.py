"""Canonical import tests for CLI output formatters."""

from r2inspect.cli.output_formatters import OutputFormatter


def test_cli_output_formatter_exports_work() -> None:
    formatter = OutputFormatter({"file_info": {"name": "sample.bin", "size": 3}})

    assert "sample.bin" in formatter.to_json()
    assert "name" in formatter.to_csv().lower()
