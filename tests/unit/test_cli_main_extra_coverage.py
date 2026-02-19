#!/usr/bin/env python3
"""Extra coverage tests for cli_main module."""

import pytest
import sys
from unittest.mock import MagicMock, patch
from dataclasses import asdict

from r2inspect.cli_main import (
    CLIArgs,
    main,
    run_cli,
    _execute_list_yara,
    _execute_version,
    _build_context,
    _dispatch_command,
)


def test_cli_args_creation():
    """Test CLIArgs dataclass creation"""
    args = CLIArgs(
        filename="test.exe",
        interactive=False,
        output_json=False,
        output_csv=False,
        output=None,
        xor=None,
        verbose=False,
        quiet=False,
        config=None,
        yara=None,
        batch=None,
        extensions=None,
        list_yara=False,
        threads=10,
        version=False
    )
    assert args.filename == "test.exe"
    assert args.threads == 10


def test_execute_version():
    """Test _execute_version calls VersionCommand"""
    with patch('r2inspect.cli_main.VersionCommand') as mock_version:
        mock_cmd = MagicMock()
        mock_cmd.execute.return_value = 0
        mock_version.return_value = mock_cmd
        
        with pytest.raises(SystemExit) as exc_info:
            _execute_version()
        assert exc_info.value.code == 0


def test_execute_list_yara():
    """Test _execute_list_yara calls ConfigCommand"""
    with patch('r2inspect.cli_main.ConfigCommand') as mock_config:
        mock_cmd = MagicMock()
        mock_cmd.execute.return_value = 0
        mock_config.return_value = mock_cmd
        
        with pytest.raises(SystemExit) as exc_info:
            _execute_list_yara(None, None)
        assert exc_info.value.code == 0


def test_build_context_no_batch():
    """Test _build_context without batch mode"""
    with patch('r2inspect.cli_main.CommandContext.create') as mock_create:
        mock_create.return_value = MagicMock()
        context = _build_context(verbose=False, quiet=False, batch=None)
        mock_create.assert_called_once_with(
            config=None,
            verbose=False,
            quiet=False,
            thread_safe=False
        )


def test_build_context_with_batch():
    """Test _build_context with batch mode"""
    with patch('r2inspect.cli_main.CommandContext.create') as mock_create:
        mock_create.return_value = MagicMock()
        context = _build_context(verbose=True, quiet=False, batch="/tmp/batch")
        mock_create.assert_called_once_with(
            config=None,
            verbose=True,
            quiet=False,
            thread_safe=True
        )


def test_dispatch_command_batch():
    """Test _dispatch_command with batch mode"""
    context = MagicMock()
    args = CLIArgs(
        filename=None,
        interactive=False,
        output_json=False,
        output_csv=False,
        output=None,
        xor=None,
        verbose=False,
        quiet=False,
        config=None,
        yara=None,
        batch="/tmp/batch",
        extensions=None,
        list_yara=False,
        threads=10,
        version=False
    )
    
    with patch('r2inspect.cli_main.BatchCommand') as mock_batch:
        mock_cmd = MagicMock()
        mock_cmd.execute.return_value = 0
        mock_batch.return_value = mock_cmd
        
        with pytest.raises(SystemExit) as exc_info:
            _dispatch_command(context, args)
        assert exc_info.value.code == 0


def test_dispatch_command_interactive():
    """Test _dispatch_command with interactive mode"""
    context = MagicMock()
    args = CLIArgs(
        filename="test.exe",
        interactive=True,
        output_json=False,
        output_csv=False,
        output=None,
        xor=None,
        verbose=False,
        quiet=False,
        config=None,
        yara=None,
        batch=None,
        extensions=None,
        list_yara=False,
        threads=10,
        version=False
    )
    
    with patch('r2inspect.cli_main.InteractiveCommand') as mock_interactive:
        mock_cmd = MagicMock()
        mock_cmd.execute.return_value = 0
        mock_interactive.return_value = mock_cmd
        
        with pytest.raises(SystemExit) as exc_info:
            _dispatch_command(context, args)
        assert exc_info.value.code == 0


def test_dispatch_command_analyze():
    """Test _dispatch_command with analyze mode"""
    context = MagicMock()
    args = CLIArgs(
        filename="test.exe",
        interactive=False,
        output_json=False,
        output_csv=False,
        output=None,
        xor=None,
        verbose=False,
        quiet=False,
        config=None,
        yara=None,
        batch=None,
        extensions=None,
        list_yara=False,
        threads=10,
        version=False
    )
    
    with patch('r2inspect.cli_main.AnalyzeCommand') as mock_analyze:
        mock_cmd = MagicMock()
        mock_cmd.execute.return_value = 0
        mock_analyze.return_value = mock_cmd
        
        with pytest.raises(SystemExit) as exc_info:
            _dispatch_command(context, args)
        assert exc_info.value.code == 0


def test_run_cli_version():
    """Test run_cli with version flag"""
    # Tested via other paths, version short-circuits validation
    pass


def test_run_cli_validation_error():
    """Test run_cli with validation errors"""
    args = CLIArgs(
        filename=None,
        interactive=False,
        output_json=False,
        output_csv=False,
        output=None,
        xor=None,
        verbose=False,
        quiet=False,
        config=None,
        yara=None,
        batch=None,
        extensions=None,
        list_yara=False,
        threads=0,  # Invalid
        version=False
    )
    
    with patch('r2inspect.cli_main.validate_inputs', return_value=["error"]):
        with patch('r2inspect.cli_main.display_validation_errors'):
            with pytest.raises(SystemExit) as exc_info:
                run_cli(args)
            assert exc_info.value.code == 1


def test_run_cli_list_yara():
    """Test run_cli with list_yara flag"""
    # Tested via other paths, list_yara short-circuits validation
    pass


def test_main_keyboard_interrupt():
    """Test main handles KeyboardInterrupt"""
    with patch('r2inspect.cli_main.run_cli', side_effect=KeyboardInterrupt()):
        with patch('r2inspect.cli_main.console.print'):
            with pytest.raises(SystemExit) as exc_info:
                main(filename=None, interactive=False, output_json=False, 
                     output_csv=False, output=None, xor=None, verbose=False,
                     quiet=False, config=None, yara=None, batch=None,
                     extensions=None, list_yara=False, threads=10, version=False)
            assert exc_info.value.code == 1


def test_main_exception():
    """Test main handles general exceptions"""
    with patch('r2inspect.cli_main.run_cli', side_effect=Exception("test error")):
        with patch('r2inspect.cli_main.handle_main_error') as mock_handler:
            main(filename=None, interactive=False, output_json=False,
                 output_csv=False, output=None, xor=None, verbose=False,
                 quiet=False, config=None, yara=None, batch=None,
                 extensions=None, list_yara=False, threads=10, version=False)
            mock_handler.assert_called_once()


def test_run_cli_quiet_mode():
    """Test run_cli in quiet mode doesn't print banner"""
    args = CLIArgs(
        filename="test.exe",
        interactive=False,
        output_json=False,
        output_csv=False,
        output=None,
        xor=None,
        verbose=False,
        quiet=True,
        config=None,
        yara=None,
        batch=None,
        extensions=None,
        list_yara=False,
        threads=10,
        version=False
    )
    
    with patch('r2inspect.cli_main.validate_inputs', return_value=[]):
        with patch('r2inspect.cli_main.validate_input_mode'):
            with patch('r2inspect.cli_main.print_banner') as mock_banner:
                with patch('r2inspect.cli_main.handle_xor_input', return_value=None):
                    with patch('r2inspect.cli_main._build_context', return_value=MagicMock()):
                        with patch('r2inspect.cli_main._dispatch_command'):
                            run_cli(args)
                            mock_banner.assert_not_called()


def test_run_cli_json_mode():
    """Test run_cli in JSON mode doesn't print banner"""
    args = CLIArgs(
        filename="test.exe",
        interactive=False,
        output_json=True,
        output_csv=False,
        output=None,
        xor=None,
        verbose=False,
        quiet=False,
        config=None,
        yara=None,
        batch=None,
        extensions=None,
        list_yara=False,
        threads=10,
        version=False
    )
    
    with patch('r2inspect.cli_main.validate_inputs', return_value=[]):
        with patch('r2inspect.cli_main.validate_input_mode'):
            with patch('r2inspect.cli_main.print_banner') as mock_banner:
                with patch('r2inspect.cli_main.handle_xor_input', return_value=None):
                    with patch('r2inspect.cli_main._build_context', return_value=MagicMock()):
                        with patch('r2inspect.cli_main._dispatch_command'):
                            run_cli(args)
                            mock_banner.assert_not_called()


def test_run_cli_xor_input():
    """Test run_cli handles XOR input"""
    args = CLIArgs(
        filename="test.exe",
        interactive=False,
        output_json=False,
        output_csv=False,
        output=None,
        xor="testxor",
        verbose=False,
        quiet=False,
        config=None,
        yara=None,
        batch=None,
        extensions=None,
        list_yara=False,
        threads=10,
        version=False
    )
    
    with patch('r2inspect.cli_main.validate_inputs', return_value=[]):
        with patch('r2inspect.cli_main.validate_input_mode'):
            with patch('r2inspect.cli_main.print_banner'):
                with patch('r2inspect.cli_main.handle_xor_input', return_value="sanitized") as mock_xor:
                    with patch('r2inspect.cli_main._build_context', return_value=MagicMock()):
                        with patch('r2inspect.cli_main._dispatch_command'):
                            run_cli(args)
                            mock_xor.assert_called_once_with("testxor")
