"""Comprehensive tests for analyze_command.py - 100% coverage target."""

import io

from rich.console import Console

from r2inspect.cli.commands.analyze_command import AnalyzeCommand
from r2inspect.cli.commands.base import CommandContext
from r2inspect.cli.output_formatters import OutputFormatter
from r2inspect.config import Config
from r2inspect.infrastructure.logging import get_logger


def _make_console():
    return Console(file=io.StringIO(), record=True, width=120)


def _make_context(tmp_path, **kwargs):
    config = Config(str(tmp_path / "config.json"))
    return CommandContext(
        console=kwargs.get("console", _make_console()),
        logger=kwargs.get("logger", get_logger()),
        config=config,
        verbose=kwargs.get("verbose", False),
        quiet=kwargs.get("quiet", False),
    )


def test_analyze_command_init(tmp_path):
    """Test AnalyzeCommand initialization."""
    cmd = AnalyzeCommand(_make_context(tmp_path))
    assert cmd is not None


def test_analyze_command_print_status_console_output(tmp_path):
    """Test _print_status_if_needed prints for console output."""
    console = _make_console()
    cmd = AnalyzeCommand(_make_context(tmp_path, console=console))
    cmd._print_status_if_needed(output_json=False, output_csv=False, output_file=None)
    text = console.export_text()
    assert "Starting analysis" in text


def test_analyze_command_print_status_json_with_file(tmp_path):
    """Test _print_status_if_needed prints when JSON output with file."""
    console = _make_console()
    cmd = AnalyzeCommand(_make_context(tmp_path, console=console))
    cmd._print_status_if_needed(output_json=True, output_csv=False, output_file="out.json")
    text = console.export_text()
    assert "Starting analysis" in text


def test_analyze_command_has_circuit_breaker_data(tmp_path):
    """Test _has_circuit_breaker_data."""
    cmd = AnalyzeCommand(_make_context(tmp_path))
    assert cmd._has_circuit_breaker_data({}) is False
    assert cmd._has_circuit_breaker_data({"failures": 0}) is False
    assert cmd._has_circuit_breaker_data({"failures": 1}) is True


def test_analyze_command_output_json_results(tmp_path):
    """Test _output_json_results writes JSON file."""
    cmd = AnalyzeCommand(_make_context(tmp_path))
    formatter = OutputFormatter({"file_info": {"name": "sample"}})
    json_file = tmp_path / "out.json"
    cmd._output_json_results(formatter, str(json_file))
    assert json_file.exists()


def test_analyze_command_output_csv_results(tmp_path):
    """Test _output_csv_results writes CSV file."""
    cmd = AnalyzeCommand(_make_context(tmp_path))
    formatter = OutputFormatter({"file_info": {"name": "sample"}})
    csv_file = tmp_path / "out.csv"
    cmd._output_csv_results(formatter, str(csv_file))
    assert csv_file.exists()


def test_analyze_command_add_statistics_to_results(tmp_path):
    """Test _add_statistics_to_results calls through to analysis_output."""
    cmd = AnalyzeCommand(_make_context(tmp_path))
    results = {"file_info": {"name": "sample"}}
    # Should not raise - just delegates to analysis_output.add_statistics_to_results
    cmd._add_statistics_to_results(results)
    # Verify it returns without error (the function modifies results in-place)
    assert isinstance(results, dict)


def test_analyze_command_handle_error_verbose(tmp_path):
    """Test _handle_error with verbose=True."""
    console = _make_console()
    cmd = AnalyzeCommand(_make_context(tmp_path, console=console))
    cmd._handle_error(ValueError("test error"), verbose=True)
    text = console.export_text()
    assert "test error" in text


def test_analyze_command_handle_error_compact(tmp_path):
    """Test _handle_error with verbose=False."""
    console = _make_console()
    cmd = AnalyzeCommand(_make_context(tmp_path, console=console))
    cmd._handle_error(ValueError("test error"), verbose=False)
    text = console.export_text()
    assert "failed" in text.lower() or "test error" in text


def test_analyze_command_setup_analysis_options(tmp_path):
    """Test _setup_analysis_options."""
    cmd = AnalyzeCommand(_make_context(tmp_path))
    options = cmd._setup_analysis_options(yara="/rules", xor="ff")
    assert options == {"yara_rules_dir": "/rules", "xor_search": "ff"}
