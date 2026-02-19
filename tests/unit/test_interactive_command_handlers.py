"""Tests for cli/commands/interactive_command.py - targeting uncovered handlers."""

from unittest.mock import Mock, MagicMock, patch

from r2inspect.cli.commands.interactive_command import InteractiveCommand
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
    """Create mock inspector with all required methods."""
    inspector = Mock()
    inspector.get_strings = Mock(return_value=["test_string"])
    inspector.get_file_info = Mock(return_value={"name": "test.exe"})
    inspector.get_pe_info = Mock(return_value={"format": "PE32"})
    inspector.get_imports = Mock(return_value=["kernel32.dll"])
    inspector.get_exports = Mock(return_value=["Export1"])
    inspector.get_sections = Mock(return_value=[{"name": ".text"}])
    inspector.__enter__ = Mock(return_value=inspector)
    inspector.__exit__ = Mock(return_value=False)
    return inspector


def test_interactive_command_should_exit():
    """Test exit command detection."""
    context = create_mock_context()
    cmd = InteractiveCommand(context)
    
    assert cmd._should_exit("quit") is True
    assert cmd._should_exit("exit") is True
    assert cmd._should_exit("q") is True
    assert cmd._should_exit("analyze") is False
    assert cmd._should_exit("") is False


def test_interactive_command_display_welcome():
    """Test welcome message display."""
    context = create_mock_context()
    cmd = InteractiveCommand(context)
    
    cmd._display_welcome()
    
    assert context.console.print.call_count > 0
    # Check that some expected text is in the calls
    calls_text = " ".join([str(call) for call in context.console.print.call_args_list])
    assert "analyze" in calls_text.lower()
    assert "strings" in calls_text.lower()


def test_interactive_command_cmd_strings():
    """Test strings command handler."""
    context = create_mock_context()
    cmd = InteractiveCommand(context)
    inspector = create_mock_inspector()
    
    cmd._cmd_strings(inspector)
    
    inspector.get_strings.assert_called_once()
    assert context.console.print.call_count >= 1


def test_interactive_command_cmd_info():
    """Test info command handler."""
    context = create_mock_context()
    cmd = InteractiveCommand(context)
    inspector = create_mock_inspector()
    
    cmd._cmd_info(inspector)
    
    inspector.get_file_info.assert_called_once()
    assert context.console.print.call_count >= 1


def test_interactive_command_cmd_pe():
    """Test PE info command handler."""
    context = create_mock_context()
    cmd = InteractiveCommand(context)
    inspector = create_mock_inspector()
    
    cmd._cmd_pe(inspector)
    
    inspector.get_pe_info.assert_called_once()
    assert context.console.print.call_count >= 1


def test_interactive_command_cmd_imports():
    """Test imports command handler."""
    context = create_mock_context()
    cmd = InteractiveCommand(context)
    inspector = create_mock_inspector()
    
    cmd._cmd_imports(inspector)
    
    inspector.get_imports.assert_called_once()
    assert context.console.print.call_count >= 1


def test_interactive_command_cmd_exports():
    """Test exports command handler."""
    context = create_mock_context()
    cmd = InteractiveCommand(context)
    inspector = create_mock_inspector()
    
    cmd._cmd_exports(inspector)
    
    inspector.get_exports.assert_called_once()
    assert context.console.print.call_count >= 1


def test_interactive_command_cmd_sections():
    """Test sections command handler."""
    context = create_mock_context()
    cmd = InteractiveCommand(context)
    inspector = create_mock_inspector()
    
    cmd._cmd_sections(inspector)
    
    inspector.get_sections.assert_called_once()
    assert context.console.print.call_count >= 1


def test_interactive_command_cmd_analyze():
    """Test analyze command handler."""
    context = create_mock_context()
    cmd = InteractiveCommand(context)
    inspector = create_mock_inspector()
    options = {}
    
    with patch("r2inspect.cli.commands.interactive_command.AnalyzeBinaryUseCase") as mock_usecase:
        mock_instance = Mock()
        mock_instance.run.return_value = {"file_info": {}}
        mock_usecase.return_value = mock_instance
        
        mock_display = Mock()
        cmd._cmd_analyze(inspector, options, mock_display)
        
        mock_instance.run.assert_called_once()
        mock_display.assert_called_once()


def test_interactive_command_execute_interactive_command_unknown():
    """Test unknown command handling."""
    context = create_mock_context()
    cmd = InteractiveCommand(context)
    inspector = create_mock_inspector()
    options = {}
    
    cmd._execute_interactive_command("unknown_command", inspector, options)
    
    # Should print error message
    calls = [str(call) for call in context.console.print.call_args_list]
    assert any("Unknown command" in str(call) for call in calls)


def test_interactive_command_execute_interactive_command_help():
    """Test help command through execute."""
    context = create_mock_context()
    cmd = InteractiveCommand(context)
    inspector = create_mock_inspector()
    options = {}
    
    cmd._execute_interactive_command("help", inspector, options)
    
    # Welcome message should be displayed
    assert context.console.print.call_count > 0


def test_interactive_command_handle_error_verbose():
    """Test error handling with verbose flag."""
    context = create_mock_context()
    cmd = InteractiveCommand(context)
    
    error = RuntimeError("Test error")
    cmd._handle_error(error, verbose=True)
    
    context.logger.error.assert_called_once()
    assert context.console.print.call_count >= 1


def test_interactive_command_handle_error_non_verbose():
    """Test error handling without verbose flag."""
    context = create_mock_context()
    cmd = InteractiveCommand(context)
    
    error = RuntimeError("Test error")
    cmd._handle_error(error, verbose=False)
    
    context.logger.error.assert_called_once()
    assert context.console.print.call_count >= 1


def test_interactive_command_keyboard_interrupt():
    """Test keyboard interrupt handling during execution."""
    context = create_mock_context()
    cmd = InteractiveCommand(context)
    
    args = {"filename": "test.exe"}
    
    with patch("r2inspect.cli.commands.interactive_command.create_inspector") as mock_create:
        inspector = create_mock_inspector()
        mock_create.return_value = inspector
        
        with patch.object(cmd, "_run_interactive_mode", side_effect=KeyboardInterrupt):
            result = cmd.execute(args)
            
            assert result == 0  # Normal exit for Ctrl+C


def test_interactive_command_exception_handling():
    """Test general exception handling."""
    context = create_mock_context()
    cmd = InteractiveCommand(context)
    
    args = {"filename": "nonexistent.exe"}
    
    with patch("r2inspect.cli.commands.interactive_command.create_inspector") as mock_create:
        mock_create.side_effect = RuntimeError("File not found")
        
        result = cmd.execute(args)
        
        assert result == 1


def test_interactive_command_execute_all_commands():
    """Test executing all interactive commands sequentially."""
    context = create_mock_context()
    cmd = InteractiveCommand(context)
    inspector = create_mock_inspector()
    options = {}
    
    commands = ["strings", "info", "pe", "imports", "exports", "sections"]
    
    with patch("r2inspect.cli.commands.interactive_command.AnalyzeBinaryUseCase"):
        for command in commands:
            cmd._execute_interactive_command(command, inspector, options)


def test_interactive_command_run_interactive_mode_error():
    """Test error handling within interactive mode loop."""
    context = create_mock_context()
    cmd = InteractiveCommand(context)
    inspector = create_mock_inspector()
    options = {}
    
    commands_iter = iter(["analyze", "quit"])
    
    original_input = __builtins__.get("input")
    try:
        __builtins__["input"] = lambda _: next(commands_iter)
        
        with patch("r2inspect.cli.commands.interactive_command.AnalyzeBinaryUseCase") as mock_usecase:
            # Make analyze raise an error
            mock_instance = Mock()
            mock_instance.run.side_effect = RuntimeError("Analysis failed")
            mock_usecase.return_value = mock_instance
            
            cmd._run_interactive_mode(inspector, options)
            
            # Should handle the error and continue
            assert context.console.print.call_count > 0
    finally:
        if original_input:
            __builtins__["input"] = original_input


def test_interactive_command_eof_error():
    """Test EOF error handling in run_interactive_mode."""
    context = create_mock_context()
    cmd = InteractiveCommand(context)
    inspector = create_mock_inspector()
    options = {}
    
    original_input = __builtins__.get("input")
    try:
        def mock_input(_):
            raise EOFError()
        
        __builtins__["input"] = mock_input
        
        cmd._run_interactive_mode(inspector, options)
        
        # Should exit cleanly
        assert True
    finally:
        if original_input:
            __builtins__["input"] = original_input
