"""Comprehensive tests for r2inspect/cli/interactive.py - 100% coverage target."""

from unittest.mock import MagicMock, Mock, patch

from r2inspect.cli.interactive import (
    _print_help,
    _show_info_table,
    run_interactive_mode,
    show_strings_only,
)


def test_show_strings_only_basic():
    """Test show_strings_only with basic strings."""
    inspector = Mock()
    inspector.get_strings.return_value = ["string1", "string2", "string3"]
    
    with patch("r2inspect.cli.interactive.console") as mock_console:
        show_strings_only(inspector)
        
        assert mock_console.print.call_count == 4
        inspector.get_strings.assert_called_once()


def test_show_strings_only_empty():
    """Test show_strings_only with empty strings."""
    inspector = Mock()
    inspector.get_strings.return_value = []
    
    with patch("r2inspect.cli.interactive.console") as mock_console:
        show_strings_only(inspector)
        
        mock_console.print.assert_called_once()


def test_print_help():
    """Test _print_help function."""
    with patch("r2inspect.cli.interactive.console") as mock_console:
        _print_help()
        
        mock_console.print.assert_called_once()
        call_args = str(mock_console.print.call_args)
        assert "analyze" in call_args or "quit" in call_args


def test_show_info_table():
    """Test _show_info_table function."""
    from r2inspect.utils.output import OutputFormatter
    
    title = "Test Title"
    data = {"key1": "value1", "key2": "value2"}
    formatter = OutputFormatter({})
    
    with patch("r2inspect.cli.interactive.console") as mock_console:
        _show_info_table(title, data, formatter)
        
        mock_console.print.assert_called_once()


def test_run_interactive_mode_quit():
    """Test interactive mode with quit command."""
    inspector = Mock()
    options = {}
    
    with patch("r2inspect.cli.interactive.console") as mock_console, \
         patch("builtins.input", side_effect=["quit"]):
        run_interactive_mode(inspector, options)
        
        assert mock_console.print.call_count >= 2


def test_run_interactive_mode_exit():
    """Test interactive mode with exit command."""
    inspector = Mock()
    options = {}
    
    with patch("r2inspect.cli.interactive.console") as mock_console, \
         patch("builtins.input", side_effect=["exit"]):
        run_interactive_mode(inspector, options)
        
        assert mock_console.print.call_count >= 2


def test_run_interactive_mode_empty_command():
    """Test interactive mode with empty command."""
    inspector = Mock()
    options = {}
    
    with patch("r2inspect.cli.interactive.console") as mock_console, \
         patch("builtins.input", side_effect=["", "quit"]):
        run_interactive_mode(inspector, options)
        
        assert mock_console.print.call_count >= 2


def test_run_interactive_mode_help():
    """Test interactive mode help command."""
    inspector = Mock()
    options = {}
    
    with patch("r2inspect.cli.interactive.console") as mock_console, \
         patch("builtins.input", side_effect=["help", "quit"]):
        run_interactive_mode(inspector, options)
        
        assert mock_console.print.call_count >= 3


def test_run_interactive_mode_strings():
    """Test interactive mode strings command."""
    inspector = Mock()
    inspector.get_strings.return_value = ["test"]
    options = {}
    
    with patch("r2inspect.cli.interactive.console") as mock_console, \
         patch("builtins.input", side_effect=["strings", "quit"]):
        run_interactive_mode(inspector, options)
        
        inspector.get_strings.assert_called_once()


def test_run_interactive_mode_info():
    """Test interactive mode info command."""
    inspector = Mock()
    inspector.get_file_info.return_value = {"size": 1024}
    options = {}
    
    with patch("r2inspect.cli.interactive.console") as mock_console, \
         patch("builtins.input", side_effect=["info", "quit"]):
        run_interactive_mode(inspector, options)
        
        inspector.get_file_info.assert_called_once()


def test_run_interactive_mode_pe():
    """Test interactive mode pe command."""
    inspector = Mock()
    inspector.get_pe_info.return_value = {"machine": "x86"}
    options = {}
    
    with patch("r2inspect.cli.interactive.console") as mock_console, \
         patch("builtins.input", side_effect=["pe", "quit"]):
        run_interactive_mode(inspector, options)
        
        inspector.get_pe_info.assert_called_once()


def test_run_interactive_mode_imports():
    """Test interactive mode imports command."""
    inspector = Mock()
    inspector.get_imports.return_value = ["kernel32.dll"]
    options = {}
    
    with patch("r2inspect.cli.interactive.console") as mock_console, \
         patch("builtins.input", side_effect=["imports", "quit"]):
        run_interactive_mode(inspector, options)
        
        inspector.get_imports.assert_called_once()


def test_run_interactive_mode_exports():
    """Test interactive mode exports command."""
    inspector = Mock()
    inspector.get_exports.return_value = ["func1"]
    options = {}
    
    with patch("r2inspect.cli.interactive.console") as mock_console, \
         patch("builtins.input", side_effect=["exports", "quit"]):
        run_interactive_mode(inspector, options)
        
        inspector.get_exports.assert_called_once()


def test_run_interactive_mode_sections():
    """Test interactive mode sections command."""
    inspector = Mock()
    inspector.get_sections.return_value = [{"name": ".text"}]
    options = {}
    
    with patch("r2inspect.cli.interactive.console") as mock_console, \
         patch("builtins.input", side_effect=["sections", "quit"]):
        run_interactive_mode(inspector, options)
        
        inspector.get_sections.assert_called_once()


def test_run_interactive_mode_analyze():
    """Test interactive mode analyze command."""
    inspector = Mock()
    options = {}
    
    with patch("r2inspect.cli.interactive.console") as mock_console, \
         patch("builtins.input", side_effect=["analyze", "quit"]), \
         patch("r2inspect.application.use_cases.AnalyzeBinaryUseCase") as mock_use_case, \
         patch("r2inspect.cli.display.display_results") as mock_display:
        
        mock_instance = Mock()
        mock_instance.run.return_value = {"test": "result"}
        mock_use_case.return_value = mock_instance
        
        run_interactive_mode(inspector, options)
        
        mock_instance.run.assert_called_once()
        mock_display.assert_called_once()


def test_run_interactive_mode_unknown_command():
    """Test interactive mode with unknown command."""
    inspector = Mock()
    options = {}
    
    with patch("r2inspect.cli.interactive.console") as mock_console, \
         patch("builtins.input", side_effect=["unknown", "quit"]):
        run_interactive_mode(inspector, options)
        
        # Check that error message was printed
        calls = [str(call) for call in mock_console.print.call_args_list]
        assert any("Unknown command" in str(call) or "help" in str(call) for call in calls)


def test_run_interactive_mode_keyboard_interrupt():
    """Test interactive mode with keyboard interrupt."""
    inspector = Mock()
    options = {}
    
    with patch("r2inspect.cli.interactive.console") as mock_console, \
         patch("builtins.input", side_effect=KeyboardInterrupt()):
        run_interactive_mode(inspector, options)
        
        # Should exit gracefully


def test_run_interactive_mode_eof_error():
    """Test interactive mode with EOF error."""
    inspector = Mock()
    options = {}
    
    with patch("r2inspect.cli.interactive.console") as mock_console, \
         patch("builtins.input", side_effect=EOFError()):
        run_interactive_mode(inspector, options)
        
        # Should exit gracefully
