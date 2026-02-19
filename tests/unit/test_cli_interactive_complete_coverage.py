from unittest.mock import MagicMock, patch
from io import StringIO
import sys
from pathlib import Path

import pytest

from r2inspect.cli.interactive import run_interactive_mode, show_strings_only
from r2inspect.factory import create_inspector


def test_run_interactive_mode_quit_command():
    inspector = MagicMock()
    options = {}
    
    with patch('builtins.input', return_value='quit'):
        run_interactive_mode(inspector, options)
    
    assert True


def test_run_interactive_mode_exit_command():
    inspector = MagicMock()
    options = {}
    
    with patch('builtins.input', return_value='exit'):
        run_interactive_mode(inspector, options)
    
    assert True


def test_run_interactive_mode_empty_command():
    inspector = MagicMock()
    options = {}
    
    inputs = ['', 'quit']
    with patch('builtins.input', side_effect=inputs):
        run_interactive_mode(inspector, options)
    
    assert True


def test_run_interactive_mode_help_command():
    inspector = MagicMock()
    options = {}
    
    inputs = ['help', 'quit']
    with patch('builtins.input', side_effect=inputs):
        run_interactive_mode(inspector, options)
    
    assert True


def test_run_interactive_mode_analyze_command():
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")

    old_stdin = sys.stdin
    sys.stdin = StringIO("analyze\nquit\n")
    try:
        with create_inspector(str(sample)) as inspector:
            run_interactive_mode(inspector, {})
    finally:
        sys.stdin = old_stdin

    assert True


def test_run_interactive_mode_strings_command():
    inspector = MagicMock()
    inspector.get_strings.return_value = ['string1', 'string2']
    options = {}
    
    inputs = ['strings', 'quit']
    with patch('builtins.input', side_effect=inputs):
        run_interactive_mode(inspector, options)
    
    inspector.get_strings.assert_called_once()


def test_run_interactive_mode_info_command():
    inspector = MagicMock()
    inspector.get_file_info.return_value = {'name': 'test.exe'}
    options = {}
    
    inputs = ['info', 'quit']
    with patch('builtins.input', side_effect=inputs):
        run_interactive_mode(inspector, options)
    
    inspector.get_file_info.assert_called_once()


def test_run_interactive_mode_pe_command():
    inspector = MagicMock()
    inspector.get_pe_info.return_value = {'type': 'PE32'}
    options = {}
    
    inputs = ['pe', 'quit']
    with patch('builtins.input', side_effect=inputs):
        run_interactive_mode(inspector, options)
    
    inspector.get_pe_info.assert_called_once()


def test_run_interactive_mode_imports_command():
    inspector = MagicMock()
    inspector.get_imports.return_value = ['kernel32.dll']
    options = {}
    
    inputs = ['imports', 'quit']
    with patch('builtins.input', side_effect=inputs):
        run_interactive_mode(inspector, options)
    
    inspector.get_imports.assert_called_once()


def test_run_interactive_mode_exports_command():
    inspector = MagicMock()
    inspector.get_exports.return_value = ['export1']
    options = {}
    
    inputs = ['exports', 'quit']
    with patch('builtins.input', side_effect=inputs):
        run_interactive_mode(inspector, options)
    
    inspector.get_exports.assert_called_once()


def test_run_interactive_mode_sections_command():
    inspector = MagicMock()
    inspector.get_sections.return_value = [{'name': '.text'}]
    options = {}
    
    inputs = ['sections', 'quit']
    with patch('builtins.input', side_effect=inputs):
        run_interactive_mode(inspector, options)
    
    inspector.get_sections.assert_called_once()


def test_run_interactive_mode_unknown_command():
    inspector = MagicMock()
    options = {}
    
    inputs = ['unknown', 'quit']
    with patch('builtins.input', side_effect=inputs):
        run_interactive_mode(inspector, options)
    
    assert True


def test_run_interactive_mode_keyboard_interrupt():
    inspector = MagicMock()
    options = {}
    
    with patch('builtins.input', side_effect=KeyboardInterrupt()):
        run_interactive_mode(inspector, options)
    
    assert True


def test_run_interactive_mode_eof_error():
    inspector = MagicMock()
    options = {}
    
    with patch('builtins.input', side_effect=EOFError()):
        run_interactive_mode(inspector, options)
    
    assert True


def test_show_strings_only():
    inspector = MagicMock()
    inspector.get_strings.return_value = ['test_string1', 'test_string2', 'test_string3']
    
    show_strings_only(inspector)
    
    inspector.get_strings.assert_called_once()
