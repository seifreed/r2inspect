#!/usr/bin/env python3
"""Tests for r2inspect/cli/commands/analysis_output.py - Output formatting and display."""

from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

from rich.console import Console

from r2inspect.cli.commands import analysis_output
from r2inspect.utils.output import OutputFormatter


def test_print_status_if_needed_console_output():
    """Test print_status_if_needed prints for console output."""
    console = MagicMock(spec=Console)
    
    analysis_output.print_status_if_needed(
        console=console,
        output_json=False,
        output_csv=False,
        output_file=None,
    )
    
    console.print.assert_called_once()


def test_print_status_if_needed_json_file():
    """Test print_status_if_needed prints for JSON file output."""
    console = MagicMock(spec=Console)
    
    analysis_output.print_status_if_needed(
        console=console,
        output_json=True,
        output_csv=False,
        output_file="/tmp/output.json",
    )
    
    console.print.assert_called_once()


def test_print_status_if_needed_csv_file():
    """Test print_status_if_needed prints for CSV file output."""
    console = MagicMock(spec=Console)
    
    analysis_output.print_status_if_needed(
        console=console,
        output_json=False,
        output_csv=True,
        output_file="/tmp/output.csv",
    )
    
    console.print.assert_called_once()


def test_print_status_if_needed_json_no_file():
    """Test print_status_if_needed does not print for JSON without file."""
    console = MagicMock(spec=Console)
    
    analysis_output.print_status_if_needed(
        console=console,
        output_json=True,
        output_csv=False,
        output_file=None,
    )
    
    console.print.assert_not_called()


def test_print_status_if_needed_csv_no_file():
    """Test print_status_if_needed does not print for CSV without file."""
    console = MagicMock(spec=Console)
    
    analysis_output.print_status_if_needed(
        console=console,
        output_json=False,
        output_csv=True,
        output_file=None,
    )
    
    console.print.assert_not_called()


def test_add_statistics_to_results():
    """Test add_statistics_to_results adds stats to results."""
    results = {"analysis": "data"}
    
    with patch("r2inspect.cli.commands.analysis_output.default_analysis_service") as mock_service:
        analysis_output.add_statistics_to_results(results)
        
        mock_service.add_statistics.assert_called_once_with(results)


def test_output_results_json():
    """Test output_results with JSON format."""
    results = {"analysis": "data"}
    console = MagicMock(spec=Console)
    
    with patch("r2inspect.cli.commands.analysis_output._output_json_results") as mock_json:
        analysis_output.output_results(
            results=results,
            output_json=True,
            output_csv=False,
            output_file=None,
            verbose=False,
            console=console,
        )
        
        mock_json.assert_called_once()


def test_output_results_csv():
    """Test output_results with CSV format."""
    results = {"analysis": "data"}
    console = MagicMock(spec=Console)
    
    with patch("r2inspect.cli.commands.analysis_output._output_csv_results") as mock_csv:
        analysis_output.output_results(
            results=results,
            output_json=False,
            output_csv=True,
            output_file=None,
            verbose=False,
            console=console,
        )
        
        mock_csv.assert_called_once()


def test_output_results_console():
    """Test output_results with console output."""
    results = {"analysis": "data"}
    console = MagicMock(spec=Console)
    
    with patch("r2inspect.cli.commands.analysis_output._output_console_results") as mock_console:
        analysis_output.output_results(
            results=results,
            output_json=False,
            output_csv=False,
            output_file=None,
            verbose=False,
            console=console,
        )
        
        mock_console.assert_called_once()


def test_output_results_console_verbose():
    """Test output_results with console output and verbose."""
    results = {"analysis": "data"}
    console = MagicMock(spec=Console)
    
    with patch("r2inspect.cli.commands.analysis_output._output_console_results") as mock_console:
        analysis_output.output_results(
            results=results,
            output_json=False,
            output_csv=False,
            output_file=None,
            verbose=True,
            console=console,
        )
        
        mock_console.assert_called_once()


def test_output_json_results_to_file():
    """Test _output_json_results writes to file."""
    console = MagicMock(spec=Console)
    formatter = MagicMock(spec=OutputFormatter)
    formatter.to_json.return_value = '{"data": "json"}'
    
    with patch("builtins.open", mock_open()) as mock_file:
        with patch("r2inspect.cli.commands.analysis_output._write_output") as mock_write:
            analysis_output._output_json_results(
                formatter=formatter,
                output_file="/tmp/output.json",
                console=console,
            )
            
            mock_write.assert_called_once()


def test_output_json_results_to_console():
    """Test _output_json_results outputs to console."""
    console = MagicMock(spec=Console)
    formatter = MagicMock(spec=OutputFormatter)
    formatter.to_json.return_value = '{"data": "json"}'
    
    with patch("r2inspect.cli.commands.analysis_output._write_output") as mock_write:
        analysis_output._output_json_results(
            formatter=formatter,
            output_file=None,
            console=console,
        )
        
        mock_write.assert_called_once()


def test_output_csv_results_to_file():
    """Test _output_csv_results writes to file."""
    console = MagicMock(spec=Console)
    formatter = MagicMock(spec=OutputFormatter)
    formatter.to_csv.return_value = 'header1,header2\nvalue1,value2'
    
    with patch("r2inspect.cli.commands.analysis_output._write_output") as mock_write:
        analysis_output._output_csv_results(
            formatter=formatter,
            output_file="/tmp/output.csv",
            console=console,
        )
        
        mock_write.assert_called_once()


def test_output_csv_results_to_console():
    """Test _output_csv_results outputs to console."""
    console = MagicMock(spec=Console)
    formatter = MagicMock(spec=OutputFormatter)
    formatter.to_csv.return_value = 'header1,header2\nvalue1,value2'
    
    with patch("r2inspect.cli.commands.analysis_output._write_output") as mock_write:
        analysis_output._output_csv_results(
            formatter=formatter,
            output_file=None,
            console=console,
        )
        
        mock_write.assert_called_once()


def test_output_console_results_no_verbose():
    """Test _output_console_results without verbose."""
    results = {"analysis": "data"}
    
    with patch("r2inspect.cli.display.display_results") as mock_display:
        analysis_output._output_console_results(results, verbose=False)
        
        mock_display.assert_called_once_with(results)


def test_output_console_results_verbose():
    """Test _output_console_results with verbose."""
    results = {"analysis": "data"}
    
    with patch("r2inspect.cli.display.display_results") as mock_display:
        with patch("r2inspect.cli.commands.analysis_output._display_verbose_statistics") as mock_stats:
            analysis_output._output_console_results(results, verbose=True)
            
            mock_display.assert_called_once_with(results)
            mock_stats.assert_called_once()


def test_display_verbose_statistics_with_errors():
    """Test _display_verbose_statistics with error statistics."""
    with patch("r2inspect.cli.commands.analysis_output._collect_statistics") as mock_collect:
        with patch("r2inspect.cli.display.display_error_statistics") as mock_display_error:
            with patch("r2inspect.cli.display.display_performance_statistics") as mock_display_perf:
                error_stats = {"total_errors": 5}
                retry_stats = {"total_retries": 0}
                circuit_stats = {}
                
                mock_collect.return_value = (error_stats, retry_stats, circuit_stats)
                
                with patch("r2inspect.cli.commands.analysis_output.default_analysis_service") as mock_service:
                    mock_service.has_circuit_breaker_data.return_value = False
                    
                    analysis_output._display_verbose_statistics()
                    
                    mock_display_error.assert_called_once()


def test_display_verbose_statistics_with_retries():
    """Test _display_verbose_statistics with retry statistics."""
    with patch("r2inspect.cli.commands.analysis_output._collect_statistics") as mock_collect:
        with patch("r2inspect.cli.display.display_error_statistics") as mock_display_error:
            with patch("r2inspect.cli.display.display_performance_statistics") as mock_display_perf:
                error_stats = {"total_errors": 0}
                retry_stats = {"total_retries": 3}
                circuit_stats = {}
                
                mock_collect.return_value = (error_stats, retry_stats, circuit_stats)
                
                with patch("r2inspect.cli.commands.analysis_output.default_analysis_service") as mock_service:
                    mock_service.has_circuit_breaker_data.return_value = False
                    
                    analysis_output._display_verbose_statistics()
                    
                    mock_display_perf.assert_called_once()


def test_display_verbose_statistics_no_stats():
    """Test _display_verbose_statistics with no statistics."""
    with patch("r2inspect.cli.commands.analysis_output._collect_statistics") as mock_collect:
        with patch("r2inspect.cli.display.display_error_statistics") as mock_display_error:
            with patch("r2inspect.cli.display.display_performance_statistics") as mock_display_perf:
                error_stats = {"total_errors": 0}
                retry_stats = {}
                circuit_stats = {}
                
                mock_collect.return_value = (error_stats, retry_stats, circuit_stats)
                
                with patch("r2inspect.cli.commands.analysis_output.default_analysis_service") as mock_service:
                    mock_service.has_circuit_breaker_data.return_value = False
                    
                    analysis_output._display_verbose_statistics()
                    
                    mock_display_error.assert_not_called()
                    mock_display_perf.assert_not_called()


def test_collect_statistics():
    """Test _collect_statistics gathers all statistics."""
    with patch("r2inspect.cli.commands.analysis_output.get_error_stats") as mock_error:
        with patch("r2inspect.cli.commands.analysis_output.get_retry_stats") as mock_retry:
            with patch("r2inspect.cli.commands.analysis_output.get_circuit_breaker_stats") as mock_circuit:
                mock_error.return_value = {"total_errors": 0}
                mock_retry.return_value = {}
                mock_circuit.return_value = {}
                
                error_stats, retry_stats, circuit_stats = analysis_output._collect_statistics()
                
                assert error_stats == {"total_errors": 0}
                assert retry_stats == {}
                assert circuit_stats == {}


def test_write_output_to_file():
    """Test _write_output writes to file."""
    console = MagicMock(spec=Console)
    
    with patch("builtins.open", mock_open()) as mock_file:
        analysis_output._write_output(
            content="test content",
            output_file="/tmp/output.txt",
            console=console,
            label="Test",
        )
        
        mock_file.assert_called_once_with("/tmp/output.txt", "w")
        console.print.assert_called_once()


def test_write_output_to_console():
    """Test _write_output prints to console."""
    console = MagicMock(spec=Console)
    
    with patch("builtins.print") as mock_print:
        analysis_output._write_output(
            content="test content",
            output_file=None,
            console=console,
            label="Test",
        )
        
        mock_print.assert_called_once_with("test content")


def test_write_output_creates_file():
    """Test _write_output creates file with correct content."""
    console = MagicMock(spec=Console)
    content = "line1\nline2\nline3"
    
    with patch("builtins.open", mock_open()) as mock_file:
        analysis_output._write_output(
            content=content,
            output_file="/tmp/test.txt",
            console=console,
            label="Output",
        )
        
        mock_file.return_value.write.assert_called_with(content)


def test_output_formatter_integration():
    """Test OutputFormatter is used correctly."""
    results = {
        "analysis": {
            "strings": ["test1", "test2"],
            "imports": ["kernel32.dll"],
        }
    }
    
    formatter = OutputFormatter(results)
    assert formatter is not None


def test_write_output_path_object():
    """Test _write_output handles Path objects."""
    console = MagicMock(spec=Console)
    output_path = Path("/tmp/output.txt")
    
    with patch("builtins.open", mock_open()) as mock_file:
        analysis_output._write_output(
            content="test",
            output_file=output_path,
            console=console,
            label="Test",
        )
        
        mock_file.assert_called_once()


def test_output_results_formatter_creation():
    """Test output_results creates OutputFormatter correctly."""
    results = {"test": "data"}
    console = MagicMock(spec=Console)
    
    with patch("r2inspect.cli.commands.analysis_output.OutputFormatter") as mock_formatter:
        with patch("r2inspect.cli.commands.analysis_output._output_console_results"):
            analysis_output.output_results(
                results=results,
                output_json=False,
                output_csv=False,
                output_file=None,
                verbose=False,
                console=console,
            )
            
            mock_formatter.assert_called_once_with(results)


def test_output_json_results_calls_formatter():
    """Test _output_json_results calls formatter.to_json."""
    console = MagicMock(spec=Console)
    formatter = MagicMock(spec=OutputFormatter)
    formatter.to_json.return_value = '{"test": "json"}'
    
    with patch("r2inspect.cli.commands.analysis_output._write_output"):
        analysis_output._output_json_results(
            formatter=formatter,
            output_file="/tmp/test.json",
            console=console,
        )
        
        formatter.to_json.assert_called_once()


def test_output_csv_results_calls_formatter():
    """Test _output_csv_results calls formatter.to_csv."""
    console = MagicMock(spec=Console)
    formatter = MagicMock(spec=OutputFormatter)
    formatter.to_csv.return_value = "col1,col2\nval1,val2"
    
    with patch("r2inspect.cli.commands.analysis_output._write_output"):
        analysis_output._output_csv_results(
            formatter=formatter,
            output_file="/tmp/test.csv",
            console=console,
        )
        
        formatter.to_csv.assert_called_once()
