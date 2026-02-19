"""Tests for cli/interactive.py - targeting uncovered code paths."""

import io
import sys
from unittest.mock import Mock, patch

from r2inspect.cli.interactive import (
    _print_help,
    run_interactive_mode,
    show_strings_only,
)


class MockInspector:
    """Mock inspector for testing interactive commands."""
    
    def __init__(self):
        self.calls = []
    
    def get_strings(self):
        self.calls.append("get_strings")
        return ["suspicious_string", "http://example.com"]
    
    def get_file_info(self):
        self.calls.append("get_file_info")
        return {
            "name": "malware.exe",
            "size": 12345,
            "md5": "abc123",
        }
    
    def get_pe_info(self):
        self.calls.append("get_pe_info")
        return {
            "format": "PE32",
            "architecture": "x86",
        }
    
    def get_imports(self):
        self.calls.append("get_imports")
        return ["kernel32.dll!CreateProcess", "ws2_32.dll!connect"]
    
    def get_exports(self):
        self.calls.append("get_exports")
        return ["DllMain", "StartService"]
    
    def get_sections(self):
        self.calls.append("get_sections")
        return [
            {"name": ".text", "size": 4096},
            {"name": ".data", "size": 2048},
        ]


def test_show_strings_only():
    """Test strings-only display function."""
    inspector = MockInspector()
    
    with patch("r2inspect.cli.interactive.console") as mock_console:
        show_strings_only(inspector)
        
        assert "get_strings" in inspector.calls
        assert mock_console.print.call_count >= 2


def test_print_help():
    """Test help command display."""
    with patch("r2inspect.cli.interactive.console") as mock_console:
        _print_help()
        
        mock_console.print.assert_called_once()
        call_args = str(mock_console.print.call_args)
        assert "analyze" in call_args
        assert "strings" in call_args


def test_run_interactive_mode_quit_command():
    """Test interactive mode with quit command."""
    inspector = MockInspector()
    options = {}
    
    original_input = __builtins__.get("input")
    try:
        __builtins__["input"] = lambda _: "quit"
        
        with patch("r2inspect.cli.interactive.console"):
            run_interactive_mode(inspector, options)
    finally:
        if original_input:
            __builtins__["input"] = original_input


def test_run_interactive_mode_empty_command():
    """Test interactive mode with empty command (just Enter)."""
    inspector = MockInspector()
    options = {}
    
    commands = ["", "", "quit"]
    command_iter = iter(commands)
    
    original_input = __builtins__.get("input")
    try:
        __builtins__["input"] = lambda _: next(command_iter)
        
        with patch("r2inspect.cli.interactive.console"):
            run_interactive_mode(inspector, options)
    finally:
        if original_input:
            __builtins__["input"] = original_input


def test_run_interactive_mode_unknown_command():
    """Test interactive mode with unknown command."""
    inspector = MockInspector()
    options = {}
    
    commands = ["invalid_cmd", "quit"]
    command_iter = iter(commands)
    
    original_input = __builtins__.get("input")
    try:
        __builtins__["input"] = lambda _: next(command_iter)
        
        with patch("r2inspect.cli.interactive.console") as mock_console:
            run_interactive_mode(inspector, options)
            
            # Should print error message
            calls = [str(call) for call in mock_console.print.call_args_list]
            assert any("Unknown command" in str(call) for call in calls)
    finally:
        if original_input:
            __builtins__["input"] = original_input


def test_run_interactive_mode_help_command():
    """Test interactive mode help command."""
    inspector = MockInspector()
    options = {}
    
    commands = ["help", "quit"]
    command_iter = iter(commands)
    
    original_input = __builtins__.get("input")
    try:
        __builtins__["input"] = lambda _: next(command_iter)
        
        with patch("r2inspect.cli.interactive.console") as mock_console:
            run_interactive_mode(inspector, options)
            
            # Help should be displayed
            assert mock_console.print.call_count > 0
    finally:
        if original_input:
            __builtins__["input"] = original_input


def test_run_interactive_mode_strings_command():
    """Test interactive mode strings command."""
    inspector = MockInspector()
    options = {}
    
    commands = ["strings", "quit"]
    command_iter = iter(commands)
    
    original_input = __builtins__.get("input")
    try:
        __builtins__["input"] = lambda _: next(command_iter)
        
        with patch("r2inspect.cli.interactive.console"):
            run_interactive_mode(inspector, options)
            
            assert "get_strings" in inspector.calls
    finally:
        if original_input:
            __builtins__["input"] = original_input


def test_run_interactive_mode_info_command():
    """Test interactive mode info command."""
    inspector = MockInspector()
    options = {}
    
    commands = ["info", "quit"]
    command_iter = iter(commands)
    
    original_input = __builtins__.get("input")
    try:
        __builtins__["input"] = lambda _: next(command_iter)
        
        with patch("r2inspect.cli.interactive.console"):
            run_interactive_mode(inspector, options)
            
            assert "get_file_info" in inspector.calls
    finally:
        if original_input:
            __builtins__["input"] = original_input


def test_run_interactive_mode_pe_command():
    """Test interactive mode PE command."""
    inspector = MockInspector()
    options = {}
    
    commands = ["pe", "quit"]
    command_iter = iter(commands)
    
    original_input = __builtins__.get("input")
    try:
        __builtins__["input"] = lambda _: next(command_iter)
        
        with patch("r2inspect.cli.interactive.console"):
            run_interactive_mode(inspector, options)
            
            assert "get_pe_info" in inspector.calls
    finally:
        if original_input:
            __builtins__["input"] = original_input


def test_run_interactive_mode_imports_command():
    """Test interactive mode imports command."""
    inspector = MockInspector()
    options = {}
    
    commands = ["imports", "quit"]
    command_iter = iter(commands)
    
    original_input = __builtins__.get("input")
    try:
        __builtins__["input"] = lambda _: next(command_iter)
        
        with patch("r2inspect.cli.interactive.console"):
            run_interactive_mode(inspector, options)
            
            assert "get_imports" in inspector.calls
    finally:
        if original_input:
            __builtins__["input"] = original_input


def test_run_interactive_mode_exports_command():
    """Test interactive mode exports command."""
    inspector = MockInspector()
    options = {}
    
    commands = ["exports", "quit"]
    command_iter = iter(commands)
    
    original_input = __builtins__.get("input")
    try:
        __builtins__["input"] = lambda _: next(command_iter)
        
        with patch("r2inspect.cli.interactive.console"):
            run_interactive_mode(inspector, options)
            
            assert "get_exports" in inspector.calls
    finally:
        if original_input:
            __builtins__["input"] = original_input


def test_run_interactive_mode_sections_command():
    """Test interactive mode sections command."""
    inspector = MockInspector()
    options = {}
    
    commands = ["sections", "quit"]
    command_iter = iter(commands)
    
    original_input = __builtins__.get("input")
    try:
        __builtins__["input"] = lambda _: next(command_iter)
        
        with patch("r2inspect.cli.interactive.console"):
            run_interactive_mode(inspector, options)
            
            assert "get_sections" in inspector.calls
    finally:
        if original_input:
            __builtins__["input"] = original_input


def test_run_interactive_mode_analyze_command():
    """Test interactive mode analyze command."""
    inspector = MockInspector()
    options = {"yara": None}
    
    commands = ["analyze", "quit"]
    command_iter = iter(commands)
    
    original_input = __builtins__.get("input")
    try:
        __builtins__["input"] = lambda _: next(command_iter)
        
        with patch("r2inspect.cli.interactive.console"):
            with patch("r2inspect.application.use_cases.AnalyzeBinaryUseCase") as mock_usecase:
                mock_instance = Mock()
                mock_instance.run.return_value = {}
                mock_usecase.return_value = mock_instance
                
                with patch("r2inspect.cli.display.display_results"):
                    run_interactive_mode(inspector, options)
                    
                    assert mock_instance.run.called
    finally:
        if original_input:
            __builtins__["input"] = original_input


def test_run_interactive_mode_eof_error():
    """Test interactive mode with EOF (Ctrl+D)."""
    inspector = MockInspector()
    options = {}
    
    original_input = __builtins__.get("input")
    try:
        def mock_input(_):
            raise EOFError()
        
        __builtins__["input"] = mock_input
        
        with patch("r2inspect.cli.interactive.console"):
            run_interactive_mode(inspector, options)
    finally:
        if original_input:
            __builtins__["input"] = original_input


def test_run_interactive_mode_keyboard_interrupt():
    """Test interactive mode with Ctrl+C."""
    inspector = MockInspector()
    options = {}
    
    original_input = __builtins__.get("input")
    try:
        def mock_input(_):
            raise KeyboardInterrupt()
        
        __builtins__["input"] = mock_input
        
        with patch("r2inspect.cli.interactive.console"):
            run_interactive_mode(inspector, options)
    finally:
        if original_input:
            __builtins__["input"] = original_input
