"""Comprehensive tests for interactive_command.py - 100% coverage target."""

from unittest.mock import Mock, patch, MagicMock

from r2inspect.cli.commands.interactive_command import InteractiveCommand


def test_execute_success():
    """Test execute method success."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.console = Mock()
    
    args = {
        "filename": "/test/file.exe",
        "config": None,
        "yara": None,
        "xor": None,
        "verbose": False
    }
    
    cmd._get_config = Mock(return_value={})
    cmd._setup_analysis_options = Mock(return_value={})
    cmd._run_interactive_mode = Mock()
    
    with patch("r2inspect.cli.commands.interactive_command.create_inspector") as mock_create:
        mock_inspector = MagicMock()
        mock_create.return_value.__enter__.return_value = mock_inspector
        
        result = cmd.execute(args)
        
        assert result == 0


def test_execute_keyboard_interrupt():
    """Test execute with keyboard interrupt."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.console = Mock()
    
    args = {
        "filename": "/test/file.exe",
        "config": None,
        "verbose": False
    }
    
    cmd._get_config = Mock(return_value={})
    cmd._setup_analysis_options = Mock(return_value={})
    
    with patch("r2inspect.cli.commands.interactive_command.create_inspector") as mock_create:
        mock_create.return_value.__enter__.side_effect = KeyboardInterrupt()
        
        result = cmd.execute(args)
        
        assert result == 0


def test_execute_exception():
    """Test execute with exception."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.console = Mock()
    
    args = {
        "filename": "/test/file.exe",
        "config": None,
        "verbose": False
    }
    
    cmd._get_config = Mock(return_value={})
    cmd._setup_analysis_options = Mock(return_value={})
    cmd._handle_error = Mock()
    
    with patch("r2inspect.cli.commands.interactive_command.create_inspector") as mock_create:
        mock_create.return_value.__enter__.side_effect = Exception("Test error")
        
        result = cmd.execute(args)
        
        assert result == 1
        cmd._handle_error.assert_called_once()


def test_run_interactive_mode_quit():
    """Test _run_interactive_mode with quit."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.console = Mock()
    cmd._display_welcome = Mock()
    
    inspector = Mock()
    options = {}
    
    with patch("builtins.input", side_effect=["quit"]):
        cmd._run_interactive_mode(inspector, options)
        
        cmd._display_welcome.assert_called_once()


def test_run_interactive_mode_empty_command():
    """Test _run_interactive_mode with empty command."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.console = Mock()
    cmd._display_welcome = Mock()
    
    inspector = Mock()
    options = {}
    
    with patch("builtins.input", side_effect=["", "quit"]):
        cmd._run_interactive_mode(inspector, options)


def test_run_interactive_mode_keyboard_interrupt():
    """Test _run_interactive_mode with keyboard interrupt."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.console = Mock()
    cmd._display_welcome = Mock()
    
    inspector = Mock()
    options = {}
    
    with patch("builtins.input", side_effect=KeyboardInterrupt()):
        cmd._run_interactive_mode(inspector, options)


def test_run_interactive_mode_eof_error():
    """Test _run_interactive_mode with EOF error."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.console = Mock()
    cmd._display_welcome = Mock()
    
    inspector = Mock()
    options = {}
    
    with patch("builtins.input", side_effect=EOFError()):
        cmd._run_interactive_mode(inspector, options)


def test_run_interactive_mode_exception():
    """Test _run_interactive_mode with exception during command."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.console = Mock()
    cmd._display_welcome = Mock()
    cmd._execute_interactive_command = Mock(side_effect=Exception("Test error"))
    
    inspector = Mock()
    options = {}
    
    with patch("builtins.input", side_effect=["analyze", "quit"]):
        cmd._run_interactive_mode(inspector, options)


def test_display_welcome():
    """Test _display_welcome method."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.console = Mock()
    
    cmd._display_welcome()
    
    assert cmd.context.console.print.call_count >= 8


def test_should_exit():
    """Test _should_exit method."""
    cmd = InteractiveCommand()
    
    assert cmd._should_exit("quit") is True
    assert cmd._should_exit("exit") is True
    assert cmd._should_exit("q") is True
    assert cmd._should_exit("analyze") is False


def test_execute_interactive_command_analyze():
    """Test _execute_interactive_command with analyze."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.console = Mock()
    cmd._cmd_analyze = Mock()
    
    inspector = Mock()
    options = {}
    
    cmd._execute_interactive_command("analyze", inspector, options)
    
    cmd._cmd_analyze.assert_called_once()


def test_execute_interactive_command_strings():
    """Test _execute_interactive_command with strings."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd._cmd_strings = Mock()
    
    inspector = Mock()
    options = {}
    
    cmd._execute_interactive_command("strings", inspector, options)
    
    cmd._cmd_strings.assert_called_once()


def test_execute_interactive_command_info():
    """Test _execute_interactive_command with info."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd._cmd_info = Mock()
    
    inspector = Mock()
    options = {}
    
    cmd._execute_interactive_command("info", inspector, options)
    
    cmd._cmd_info.assert_called_once()


def test_execute_interactive_command_pe():
    """Test _execute_interactive_command with pe."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd._cmd_pe = Mock()
    
    inspector = Mock()
    options = {}
    
    cmd._execute_interactive_command("pe", inspector, options)
    
    cmd._cmd_pe.assert_called_once()


def test_execute_interactive_command_imports():
    """Test _execute_interactive_command with imports."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd._cmd_imports = Mock()
    
    inspector = Mock()
    options = {}
    
    cmd._execute_interactive_command("imports", inspector, options)
    
    cmd._cmd_imports.assert_called_once()


def test_execute_interactive_command_exports():
    """Test _execute_interactive_command with exports."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd._cmd_exports = Mock()
    
    inspector = Mock()
    options = {}
    
    cmd._execute_interactive_command("exports", inspector, options)
    
    cmd._cmd_exports.assert_called_once()


def test_execute_interactive_command_sections():
    """Test _execute_interactive_command with sections."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd._cmd_sections = Mock()
    
    inspector = Mock()
    options = {}
    
    cmd._execute_interactive_command("sections", inspector, options)
    
    cmd._cmd_sections.assert_called_once()


def test_execute_interactive_command_help():
    """Test _execute_interactive_command with help."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd._display_welcome = Mock()
    
    inspector = Mock()
    options = {}
    
    cmd._execute_interactive_command("help", inspector, options)
    
    cmd._display_welcome.assert_called_once()


def test_execute_interactive_command_unknown():
    """Test _execute_interactive_command with unknown command."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.console = Mock()
    
    inspector = Mock()
    options = {}
    
    cmd._execute_interactive_command("unknown", inspector, options)
    
    assert cmd.context.console.print.call_count >= 2


def test_cmd_analyze():
    """Test _cmd_analyze method."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.console = Mock()
    
    inspector = Mock()
    options = {}
    display_results = Mock()
    
    with patch("r2inspect.cli.commands.interactive_command.AnalyzeBinaryUseCase") as mock_use_case:
        mock_instance = Mock()
        mock_instance.run.return_value = {"test": "result"}
        mock_use_case.return_value = mock_instance
        
        cmd._cmd_analyze(inspector, options, display_results)
        
        mock_instance.run.assert_called_once()
        display_results.assert_called_once()


def test_cmd_strings():
    """Test _cmd_strings method."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.console = Mock()
    
    inspector = Mock()
    inspector.get_strings.return_value = ["string1", "string2"]
    
    cmd._cmd_strings(inspector)
    
    inspector.get_strings.assert_called_once()


def test_cmd_info():
    """Test _cmd_info method."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.console = Mock()
    
    inspector = Mock()
    inspector.get_file_info.return_value = {"size": 1024}
    
    cmd._cmd_info(inspector)
    
    inspector.get_file_info.assert_called_once()


def test_cmd_pe():
    """Test _cmd_pe method."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.console = Mock()
    
    inspector = Mock()
    inspector.get_pe_info.return_value = {"machine": "x86"}
    
    cmd._cmd_pe(inspector)
    
    inspector.get_pe_info.assert_called_once()


def test_cmd_imports():
    """Test _cmd_imports method."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.console = Mock()
    
    inspector = Mock()
    inspector.get_imports.return_value = ["import1"]
    
    cmd._cmd_imports(inspector)
    
    inspector.get_imports.assert_called_once()


def test_cmd_exports():
    """Test _cmd_exports method."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.console = Mock()
    
    inspector = Mock()
    inspector.get_exports.return_value = ["export1"]
    
    cmd._cmd_exports(inspector)
    
    inspector.get_exports.assert_called_once()


def test_cmd_sections():
    """Test _cmd_sections method."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.console = Mock()
    
    inspector = Mock()
    inspector.get_sections.return_value = [{"name": ".text"}]
    
    cmd._cmd_sections(inspector)
    
    inspector.get_sections.assert_called_once()


def test_handle_error_verbose():
    """Test _handle_error with verbose mode."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.logger = Mock()
    cmd.context.console = Mock()
    
    error = Exception("Test error")
    
    cmd._handle_error(error, verbose=True)
    
    cmd.context.logger.error.assert_called_once()


def test_handle_error_non_verbose():
    """Test _handle_error without verbose mode."""
    cmd = InteractiveCommand()
    cmd.context = Mock()
    cmd.context.logger = Mock()
    cmd.context.console = Mock()
    
    error = Exception("Test error")
    
    cmd._handle_error(error, verbose=False)
    
    cmd.context.logger.error.assert_called_once()
