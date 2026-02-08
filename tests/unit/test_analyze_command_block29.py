from __future__ import annotations

from pathlib import Path

from r2inspect.cli.commands.analyze_command import AnalyzeCommand
from r2inspect.cli.commands.base import CommandContext
from r2inspect.utils.output import OutputFormatter


def test_analyze_command_helpers(tmp_path: Path, capsys):
    cmd = AnalyzeCommand(CommandContext.create())

    cmd._print_status_if_needed(output_json=False, output_csv=False, output_file=None)
    assert "Starting analysis" in capsys.readouterr().out

    cmd._print_status_if_needed(output_json=True, output_csv=False, output_file="out.json")
    assert "Starting analysis" in capsys.readouterr().out

    assert cmd._has_circuit_breaker_data({}) is False
    assert cmd._has_circuit_breaker_data({"failures": 0}) is False
    assert cmd._has_circuit_breaker_data({"failures": 1}) is True

    formatter = OutputFormatter({"file_info": {"name": "sample"}})
    json_file = tmp_path / "out.json"
    cmd._output_json_results(formatter, str(json_file))
    assert json_file.exists()

    csv_file = tmp_path / "out.csv"
    cmd._output_csv_results(formatter, str(csv_file))
    assert csv_file.exists()
