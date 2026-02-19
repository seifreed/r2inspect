"""Tests for cli/commands/analyze_command.py - edge cases and error paths."""

from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from r2inspect.cli.commands.analyze_command import AnalyzeCommand
from r2inspect.cli.commands.base import CommandContext


def create_mock_context():
    """Create mock command context."""
    context = Mock(spec=CommandContext)
    context.console = Mock()
    context.logger = Mock()
    context.config = None
    context.verbose = False
    context.quiet = False
    return context


def create_mock_inspector():
    """Create mock inspector."""
    inspector = Mock()
    inspector.__enter__ = Mock(return_value=inspector)
    inspector.__exit__ = Mock(return_value=False)
    return inspector


def test_analyze_command_keyboard_interrupt():
    """Test handling keyboard interrupt during analysis."""
    context = create_mock_context()
    cmd = AnalyzeCommand(context)
    
    args = {
        "filename": "test.exe",
        "config": None,
        "verbose": False,
    }
    
    with patch("r2inspect.cli.commands.analyze_command.create_inspector") as mock_create:
        inspector = create_mock_inspector()
        mock_create.return_value = inspector
        
        with patch.object(cmd, "_run_analysis", side_effect=KeyboardInterrupt):
            result = cmd.execute(args)
            
            assert result == 1
            context.console.print.assert_called()


def test_analyze_command_exception_handling():
    """Test handling general exception during analysis."""
    context = create_mock_context()
    cmd = AnalyzeCommand(context)
    
    args = {
        "filename": "test.exe",
        "config": None,
        "verbose": False,
    }
    
    with patch("r2inspect.cli.commands.analyze_command.create_inspector") as mock_create:
        mock_create.side_effect = RuntimeError("Analysis failed")
        
        result = cmd.execute(args)
        
        assert result == 1
        context.logger.error.assert_called()


def test_analyze_command_with_threads():
    """Test analyze command with thread configuration."""
    context = create_mock_context()
    cmd = AnalyzeCommand(context)
    
    mock_config = Mock()
    mock_config.apply_overrides = Mock()
    
    args = {
        "filename": "test.exe",
        "config": None,
        "verbose": False,
        "threads": 4,
    }
    
    with patch("r2inspect.cli.commands.analyze_command.create_inspector") as mock_create:
        inspector = create_mock_inspector()
        mock_create.return_value = inspector
        
        with patch.object(cmd, "_get_config", return_value=mock_config):
            with patch("r2inspect.cli.commands.analyze_command.AnalyzeBinaryUseCase") as mock_usecase:
                mock_instance = Mock()
                mock_instance.run.return_value = {}
                mock_usecase.return_value = mock_instance
                
                with patch("r2inspect.cli.commands.analyze_command.analysis_output"):
                    result = cmd.execute(args)
                    
                    assert result == 0


def test_analyze_command_handle_error_verbose():
    """Test error handling with verbose output."""
    context = create_mock_context()
    cmd = AnalyzeCommand(context)
    
    error = RuntimeError("Test error message")
    cmd._handle_error(error, verbose=True)
    
    context.logger.error.assert_called_once()
    # Should print error and traceback
    assert context.console.print.call_count >= 1


def test_analyze_command_handle_error_non_verbose():
    """Test error handling without verbose output."""
    context = create_mock_context()
    cmd = AnalyzeCommand(context)
    
    error = RuntimeError("Test error message")
    cmd._handle_error(error, verbose=False)
    
    context.logger.error.assert_called_once()
    # Should print brief error message
    assert context.console.print.call_count >= 1


def test_analyze_command_run_analysis_json_output():
    """Test running analysis with JSON output."""
    context = create_mock_context()
    cmd = AnalyzeCommand(context)
    inspector = create_mock_inspector()
    
    with patch("r2inspect.cli.commands.analyze_command.AnalyzeBinaryUseCase") as mock_usecase:
        mock_instance = Mock()
        mock_instance.run.return_value = {"file_info": {}}
        mock_usecase.return_value = mock_instance
        
        with patch("r2inspect.cli.commands.analyze_command.analysis_output") as mock_output:
            cmd._run_analysis(
                inspector=inspector,
                options={},
                output_json=True,
                output_csv=False,
                output_file=None,
                verbose=False,
            )
            
            mock_output.print_status_if_needed.assert_called_once()
            mock_output.output_results.assert_called_once()


def test_analyze_command_run_analysis_csv_output():
    """Test running analysis with CSV output."""
    context = create_mock_context()
    cmd = AnalyzeCommand(context)
    inspector = create_mock_inspector()
    
    with patch("r2inspect.cli.commands.analyze_command.AnalyzeBinaryUseCase") as mock_usecase:
        mock_instance = Mock()
        mock_instance.run.return_value = {"file_info": {}}
        mock_usecase.return_value = mock_instance
        
        with patch("r2inspect.cli.commands.analyze_command.analysis_output") as mock_output:
            cmd._run_analysis(
                inspector=inspector,
                options={},
                output_json=False,
                output_csv=True,
                output_file=None,
                verbose=False,
            )
            
            mock_output.print_status_if_needed.assert_called_once()
            mock_output.output_results.assert_called_once()


def test_analyze_command_run_analysis_with_output_file():
    """Test running analysis with output file specified."""
    context = create_mock_context()
    cmd = AnalyzeCommand(context)
    inspector = create_mock_inspector()
    
    with patch("r2inspect.cli.commands.analyze_command.AnalyzeBinaryUseCase") as mock_usecase:
        mock_instance = Mock()
        mock_instance.run.return_value = {"file_info": {}}
        mock_usecase.return_value = mock_instance
        
        with patch("r2inspect.cli.commands.analyze_command.analysis_output") as mock_output:
            cmd._run_analysis(
                inspector=inspector,
                options={},
                output_json=True,
                output_csv=False,
                output_file=Path("output.json"),
                verbose=False,
            )
            
            mock_output.output_results.assert_called_once()


def test_analyze_command_print_status_if_needed():
    """Test print status if needed method."""
    context = create_mock_context()
    cmd = AnalyzeCommand(context)
    
    with patch("r2inspect.cli.commands.analyze_command.analysis_output") as mock_output:
        cmd._print_status_if_needed(
            output_json=True,
            output_csv=False,
            output_file=None,
        )
        
        mock_output.print_status_if_needed.assert_called_once_with(
            context.console,
            True,
            False,
            None,
        )


def test_analyze_command_output_results():
    """Test output results method."""
    context = create_mock_context()
    cmd = AnalyzeCommand(context)
    
    results = {"file_info": {"name": "test.exe"}}
    
    with patch("r2inspect.cli.commands.analyze_command.analysis_output") as mock_output:
        cmd._output_results(
            results=results,
            output_json=True,
            output_csv=False,
            output_file=None,
            verbose=True,
        )
        
        mock_output.output_results.assert_called_once()


def test_analyze_command_with_yara_and_xor():
    """Test analyze command with YARA and XOR options."""
    context = create_mock_context()
    cmd = AnalyzeCommand(context)
    
    args = {
        "filename": "test.exe",
        "config": None,
        "verbose": False,
        "yara": "/path/to/rules",
        "xor": "searchstring",
    }
    
    with patch("r2inspect.cli.commands.analyze_command.create_inspector") as mock_create:
        inspector = create_mock_inspector()
        mock_create.return_value = inspector
        
        with patch("r2inspect.cli.commands.analyze_command.AnalyzeBinaryUseCase") as mock_usecase:
            mock_instance = Mock()
            mock_instance.run.return_value = {}
            mock_usecase.return_value = mock_instance
            
            with patch("r2inspect.cli.commands.analyze_command.analysis_output"):
                with patch.object(cmd, "_setup_analysis_options", return_value={}) as mock_setup:
                    result = cmd.execute(args)
                    
                    assert result == 0
                    mock_setup.assert_called_once()


def test_analyze_command_output_json_results():
    """Test JSON results output."""
    context = create_mock_context()
    cmd = AnalyzeCommand(context)
    
    formatter = Mock()
    
    with patch("r2inspect.cli.commands.analyze_command.analysis_output") as mock_output:
        cmd._output_json_results(formatter, None)
        
        mock_output._output_json_results.assert_called_once_with(
            formatter, None, context.console
        )


def test_analyze_command_output_csv_results():
    """Test CSV results output."""
    context = create_mock_context()
    cmd = AnalyzeCommand(context)
    
    formatter = Mock()
    
    with patch("r2inspect.cli.commands.analyze_command.analysis_output") as mock_output:
        cmd._output_csv_results(formatter, None)
        
        mock_output._output_csv_results.assert_called_once_with(
            formatter, None, context.console
        )


def test_analyze_command_output_console_results():
    """Test console results output."""
    context = create_mock_context()
    cmd = AnalyzeCommand(context)
    
    results = {"file_info": {}}
    
    with patch("r2inspect.cli.commands.analyze_command.analysis_output") as mock_output:
        cmd._output_console_results(results, verbose=True)
        
        mock_output._output_console_results.assert_called_once_with(results, True)


def test_analyze_command_display_verbose_statistics():
    """Test verbose statistics display."""
    context = create_mock_context()
    cmd = AnalyzeCommand(context)
    
    with patch("r2inspect.cli.commands.analyze_command.analysis_output") as mock_output:
        cmd._display_verbose_statistics()
        
        mock_output._display_verbose_statistics.assert_called_once()


def test_analyze_command_complete_flow_verbose():
    """Test complete analysis flow with verbose output."""
    context = create_mock_context()
    cmd = AnalyzeCommand(context)
    
    args = {
        "filename": "test.exe",
        "config": None,
        "verbose": True,
        "output_json": True,
        "output_csv": True,
        "output": "results.json",
    }
    
    with patch("r2inspect.cli.commands.analyze_command.create_inspector") as mock_create:
        inspector = create_mock_inspector()
        mock_create.return_value = inspector
        
        with patch("r2inspect.cli.commands.analyze_command.AnalyzeBinaryUseCase") as mock_usecase:
            mock_instance = Mock()
            mock_instance.run.return_value = {"file_info": {}}
            mock_usecase.return_value = mock_instance
            
            with patch("r2inspect.cli.commands.analyze_command.analysis_output"):
                result = cmd.execute(args)
                
                assert result == 0
