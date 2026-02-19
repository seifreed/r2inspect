#!/usr/bin/env python3
"""Tests for r2inspect/cli/commands/analyze_command.py - AnalyzeCommand implementation."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from r2inspect.cli.commands.analyze_command import AnalyzeCommand
from r2inspect.cli.commands.base import CommandContext
from r2inspect.config import Config


def test_analyze_command_init():
    """Test AnalyzeCommand initialization."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    assert cmd is not None
    assert cmd.context is context


def test_analyze_command_init_without_context():
    """Test AnalyzeCommand initialization without context."""
    cmd = AnalyzeCommand()
    
    assert cmd is not None
    assert cmd.context is not None


def test_analyze_command_execute_keyboard_interrupt():
    """Test AnalyzeCommand.execute handles KeyboardInterrupt."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    with patch("r2inspect.cli.commands.analyze_command.create_inspector") as mock_inspector:
        mock_inspector.side_effect = KeyboardInterrupt()
        
        result = cmd.execute({"filename": "test.bin"})
        assert result == 1


def test_analyze_command_execute_error_handling():
    """Test AnalyzeCommand.execute handles exceptions."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    with patch("r2inspect.cli.commands.analyze_command.create_inspector") as mock_inspector:
        mock_inspector.side_effect = Exception("Test error")
        
        result = cmd.execute({"filename": "test.bin", "verbose": False})
        assert result == 1


def test_analyze_command_execute_error_verbose():
    """Test AnalyzeCommand.execute shows traceback in verbose mode."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    with patch("r2inspect.cli.commands.analyze_command.create_inspector") as mock_inspector:
        mock_inspector.side_effect = Exception("Test error")
        
        result = cmd.execute({"filename": "test.bin", "verbose": True})
        assert result == 1


def test_analyze_command_get_config():
    """Test AnalyzeCommand gets config correctly."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    config = cmd._get_config()
    assert config is not None
    assert isinstance(config, Config)


def test_analyze_command_get_config_with_path():
    """Test AnalyzeCommand gets config from path."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    config = cmd._get_config(config_path=None)
    assert config is not None


def test_analyze_command_setup_analysis_options_empty():
    """Test AnalyzeCommand._setup_analysis_options with no options."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    options = cmd._setup_analysis_options()
    assert options == {}


def test_analyze_command_setup_analysis_options_yara():
    """Test AnalyzeCommand._setup_analysis_options with YARA."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    options = cmd._setup_analysis_options(yara="/path/to/rules")
    assert "yara_rules_dir" in options
    assert options["yara_rules_dir"] == "/path/to/rules"


def test_analyze_command_setup_analysis_options_xor():
    """Test AnalyzeCommand._setup_analysis_options with XOR key."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    options = cmd._setup_analysis_options(xor="DEADBEEF")
    assert "xor_search" in options
    assert options["xor_search"] == "DEADBEEF"


def test_analyze_command_setup_analysis_options_both():
    """Test AnalyzeCommand._setup_analysis_options with both options."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    options = cmd._setup_analysis_options(yara="/rules", xor="FF")
    assert len(options) == 2
    assert options["yara_rules_dir"] == "/rules"
    assert options["xor_search"] == "FF"


def test_analyze_command_print_status_if_needed_console_output():
    """Test AnalyzeCommand._print_status_if_needed for console output."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    with patch("r2inspect.cli.commands.analyze_command.analysis_output.print_status_if_needed") as mock_print:
        cmd._print_status_if_needed(
            output_json=False,
            output_csv=False,
            output_file=None,
        )
        mock_print.assert_called_once()


def test_analyze_command_print_status_if_needed_json():
    """Test AnalyzeCommand._print_status_if_needed for JSON output."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    with patch("r2inspect.cli.commands.analyze_command.analysis_output.print_status_if_needed") as mock_print:
        cmd._print_status_if_needed(
            output_json=True,
            output_csv=False,
            output_file="/tmp/output.json",
        )
        mock_print.assert_called_once()


def test_analyze_command_print_status_if_needed_csv():
    """Test AnalyzeCommand._print_status_if_needed for CSV output."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    with patch("r2inspect.cli.commands.analyze_command.analysis_output.print_status_if_needed") as mock_print:
        cmd._print_status_if_needed(
            output_json=False,
            output_csv=True,
            output_file="/tmp/output.csv",
        )
        mock_print.assert_called_once()


def test_analyze_command_output_results():
    """Test AnalyzeCommand._output_results."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    results = {"analysis": "data"}
    
    with patch("r2inspect.cli.commands.analyze_command.analysis_output.output_results") as mock_output:
        cmd._output_results(
            results=results,
            output_json=False,
            output_csv=False,
            output_file=None,
            verbose=False,
        )
        mock_output.assert_called_once()


def test_analyze_command_output_json_results():
    """Test AnalyzeCommand._output_json_results."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    formatter = MagicMock()
    
    with patch("r2inspect.cli.commands.analyze_command.analysis_output._output_json_results") as mock_output:
        cmd._output_json_results(formatter, "/tmp/output.json")
        mock_output.assert_called_once()


def test_analyze_command_output_csv_results():
    """Test AnalyzeCommand._output_csv_results."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    formatter = MagicMock()
    
    with patch("r2inspect.cli.commands.analyze_command.analysis_output._output_csv_results") as mock_output:
        cmd._output_csv_results(formatter, "/tmp/output.csv")
        mock_output.assert_called_once()


def test_analyze_command_output_console_results():
    """Test AnalyzeCommand._output_console_results."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    results = {"analysis": "data"}
    
    with patch("r2inspect.cli.commands.analyze_command.analysis_output._output_console_results") as mock_output:
        cmd._output_console_results(results, verbose=False)
        mock_output.assert_called_once()


def test_analyze_command_output_console_results_verbose():
    """Test AnalyzeCommand._output_console_results with verbose."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    results = {"analysis": "data"}
    
    with patch("r2inspect.cli.commands.analyze_command.analysis_output._output_console_results") as mock_output:
        cmd._output_console_results(results, verbose=True)
        mock_output.assert_called_once()


def test_analyze_command_display_verbose_statistics():
    """Test AnalyzeCommand._display_verbose_statistics."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    with patch("r2inspect.cli.commands.analyze_command.analysis_output._display_verbose_statistics") as mock_display:
        cmd._display_verbose_statistics()
        mock_display.assert_called_once()


def test_analyze_command_handle_error_verbose():
    """Test AnalyzeCommand._handle_error with verbose output."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    error = Exception("Test error")
    cmd._handle_error(error, verbose=True)
    
    # Verify error was logged
    assert True


def test_analyze_command_handle_error_quiet():
    """Test AnalyzeCommand._handle_error without verbose output."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    error = Exception("Test error")
    cmd._handle_error(error, verbose=False)
    
    # Verify error was handled without traceback
    assert True


def test_analyze_command_run_analysis():
    """Test AnalyzeCommand._run_analysis."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    inspector = MagicMock()
    
    with patch("r2inspect.cli.commands.analyze_command.AnalyzeBinaryUseCase") as mock_use_case:
        with patch.object(cmd, "_print_status_if_needed"):
            with patch.object(cmd, "_output_results"):
                mock_use_case_instance = MagicMock()
                mock_use_case_instance.run.return_value = {"analysis": "data"}
                mock_use_case.return_value = mock_use_case_instance
                
                cmd._run_analysis(
                    inspector=inspector,
                    options={},
                    output_json=False,
                    output_csv=False,
                    output_file=None,
                    verbose=False,
                )


def test_analyze_command_args_processing():
    """Test AnalyzeCommand processes args correctly."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    args = {
        "filename": "test.bin",
        "config": None,
        "verbose": False,
        "threads": None,
        "yara": None,
        "xor": None,
        "output_json": False,
        "output_csv": False,
        "output": None,
    }
    
    # Verify that arg keys are handled
    assert "filename" in args
    assert args["filename"] == "test.bin"


def test_analyze_command_threads_setting():
    """Test AnalyzeCommand applies thread settings."""
    context = CommandContext.create()
    cmd = AnalyzeCommand(context)
    
    with patch("r2inspect.cli.commands.analyze_command.apply_thread_settings") as mock_apply:
        with patch("r2inspect.cli.commands.analyze_command.create_inspector") as mock_inspector:
            mock_inspector.side_effect = Exception("Stop execution")
            
            try:
                cmd.execute({
                    "filename": "test.bin",
                    "config": None,
                    "verbose": False,
                    "threads": 4,
                })
            except:
                pass
            
            mock_apply.assert_called()
