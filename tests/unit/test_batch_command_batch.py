#!/usr/bin/env python3
"""
Comprehensive tests for r2inspect/cli/commands/batch_command.py module.
Tests batch command execution, error handling, and configuration.
Coverage target: 100% (currently 16%)
"""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from r2inspect.cli.commands.batch_command import BatchCommand


@pytest.fixture
def batch_command():
    """Create a BatchCommand instance for testing"""
    command = BatchCommand()
    command.context = MagicMock()
    command.context.console = MagicMock()
    command.context.logger = MagicMock()
    return command


@pytest.fixture
def sample_batch_dir(tmp_path):
    """Create a sample batch directory with test files"""
    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()
    (batch_dir / "file1.exe").write_bytes(b"MZ" + b"\x00" * 100)
    (batch_dir / "file2.dll").write_bytes(b"MZ" + b"\x00" * 100)
    return batch_dir


def test_batch_command_initialization():
    """Test BatchCommand can be initialized"""
    command = BatchCommand()
    assert command is not None


def test_execute_basic_success(batch_command, sample_batch_dir):
    """Test successful batch command execution"""
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "yara": None,
        "xor": None,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1,
        "verbose": False,
        "quiet": True
    }
    
    with patch.object(batch_command, '_run_batch_analysis'):
        result = batch_command.execute(args)
        assert result == 0


def test_execute_with_json_output(batch_command, sample_batch_dir):
    """Test batch command execution with JSON output"""
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "output_json": True,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1,
        "verbose": False,
        "quiet": True
    }
    
    with patch.object(batch_command, '_run_batch_analysis'):
        result = batch_command.execute(args)
        assert result == 0


def test_execute_with_csv_output(batch_command, sample_batch_dir):
    """Test batch command execution with CSV output"""
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "output_json": False,
        "output_csv": True,
        "output": None,
        "extensions": None,
        "threads": 1,
        "verbose": False,
        "quiet": True
    }
    
    with patch.object(batch_command, '_run_batch_analysis'):
        result = batch_command.execute(args)
        assert result == 0


def test_execute_with_both_outputs(batch_command, sample_batch_dir):
    """Test batch command execution with both JSON and CSV output"""
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "output_json": True,
        "output_csv": True,
        "output": None,
        "extensions": None,
        "threads": 1,
        "verbose": False,
        "quiet": True
    }
    
    with patch.object(batch_command, '_run_batch_analysis'):
        result = batch_command.execute(args)
        assert result == 0


def test_execute_with_extensions(batch_command, sample_batch_dir):
    """Test batch command execution with file extensions filter"""
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "extensions": "exe,dll",
        "output_json": False,
        "output_csv": False,
        "output": None,
        "threads": 1,
        "verbose": False,
        "quiet": True
    }
    
    with patch.object(batch_command, '_run_batch_analysis'):
        result = batch_command.execute(args)
        assert result == 0


def test_execute_with_yara(batch_command, sample_batch_dir, tmp_path):
    """Test batch command execution with custom YARA rules"""
    yara_dir = tmp_path / "yara"
    yara_dir.mkdir()
    
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "yara": str(yara_dir),
        "xor": None,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1,
        "verbose": False,
        "quiet": True
    }
    
    with patch.object(batch_command, '_run_batch_analysis'):
        result = batch_command.execute(args)
        assert result == 0


def test_execute_with_xor(batch_command, sample_batch_dir):
    """Test batch command execution with XOR search"""
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "yara": None,
        "xor": "test_string",
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1,
        "verbose": False,
        "quiet": True
    }
    
    with patch.object(batch_command, '_run_batch_analysis'):
        result = batch_command.execute(args)
        assert result == 0


def test_execute_with_verbose(batch_command, sample_batch_dir):
    """Test batch command execution in verbose mode"""
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "verbose": True,
        "quiet": False,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1
    }
    
    with patch.object(batch_command, '_run_batch_analysis'):
        result = batch_command.execute(args)
        assert result == 0


def test_execute_with_multiple_threads(batch_command, sample_batch_dir):
    """Test batch command execution with multiple threads"""
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "threads": 4,
        "verbose": False,
        "quiet": True,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None
    }
    
    with patch.object(batch_command, '_run_batch_analysis'):
        result = batch_command.execute(args)
        assert result == 0


def test_execute_keyboard_interrupt(batch_command, sample_batch_dir):
    """Test batch command handles keyboard interrupt"""
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "verbose": False,
        "quiet": True,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1
    }
    
    with patch.object(batch_command, '_run_batch_analysis', side_effect=KeyboardInterrupt):
        result = batch_command.execute(args)
        assert result == 1
        batch_command.context.console.print.assert_called()


def test_execute_exception_verbose(batch_command, sample_batch_dir):
    """Test batch command handles exceptions in verbose mode"""
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "verbose": True,
        "quiet": False,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1
    }
    
    with patch.object(batch_command, '_run_batch_analysis', side_effect=ValueError("Test error")):
        result = batch_command.execute(args)
        assert result == 1
        batch_command.context.logger.error.assert_called()


def test_execute_exception_normal(batch_command, sample_batch_dir):
    """Test batch command handles exceptions in normal mode"""
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "verbose": False,
        "quiet": True,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1
    }
    
    with patch.object(batch_command, '_run_batch_analysis', side_effect=RuntimeError("Test error")):
        result = batch_command.execute(args)
        assert result == 1


def test_setup_batch_mode_default():
    """Test batch mode setup with defaults"""
    command = BatchCommand()
    recursive, auto_detect, output_dir = command._setup_batch_mode(
        _batch="/path/to/batch",
        extensions=None,
        output_json=False,
        output_csv=False,
        output=None
    )
    
    assert recursive is True
    assert auto_detect is True
    assert output_dir is None


def test_setup_batch_mode_with_extensions():
    """Test batch mode setup with extensions"""
    command = BatchCommand()
    recursive, auto_detect, output_dir = command._setup_batch_mode(
        _batch="/path/to/batch",
        extensions="exe,dll",
        output_json=False,
        output_csv=False,
        output=None
    )
    
    assert recursive is True
    assert auto_detect is False
    assert output_dir is None


def test_setup_batch_mode_json_output():
    """Test batch mode setup with JSON output"""
    command = BatchCommand()
    recursive, auto_detect, output_dir = command._setup_batch_mode(
        _batch="/path/to/batch",
        extensions=None,
        output_json=True,
        output_csv=False,
        output=None
    )
    
    assert recursive is True
    assert auto_detect is True
    assert output_dir == "output"


def test_setup_batch_mode_csv_output():
    """Test batch mode setup with CSV output"""
    command = BatchCommand()
    recursive, auto_detect, output_dir = command._setup_batch_mode(
        _batch="/path/to/batch",
        extensions=None,
        output_json=False,
        output_csv=True,
        output=None
    )
    
    assert recursive is True
    assert auto_detect is True
    assert output_dir == "output"


def test_setup_batch_mode_custom_output():
    """Test batch mode setup with custom output directory"""
    command = BatchCommand()
    recursive, auto_detect, output_dir = command._setup_batch_mode(
        _batch="/path/to/batch",
        extensions=None,
        output_json=True,
        output_csv=True,
        output="/custom/output"
    )
    
    assert output_dir == "/custom/output"


def test_setup_analysis_options_default():
    """Test analysis options setup with defaults"""
    command = BatchCommand()
    options = command._setup_analysis_options()
    
    assert options["detect_packer"] is True
    assert options["detect_crypto"] is True
    assert options["detect_av"] is True
    assert options["full_analysis"] is True


def test_setup_analysis_options_with_yara():
    """Test analysis options setup with YARA rules"""
    command = BatchCommand()
    options = command._setup_analysis_options(yara="/path/to/yara")
    
    assert options["custom_yara"] == "/path/to/yara"


def test_setup_analysis_options_with_xor():
    """Test analysis options setup with XOR search"""
    command = BatchCommand()
    options = command._setup_analysis_options(xor="test_xor")
    
    assert options["xor_search"] == "test_xor"


def test_setup_analysis_options_with_both():
    """Test analysis options setup with both YARA and XOR"""
    command = BatchCommand()
    options = command._setup_analysis_options(yara="/path/to/yara", xor="test_xor")
    
    assert options["custom_yara"] == "/path/to/yara"
    assert options["xor_search"] == "test_xor"


def test_configure_batch_logging_verbose():
    """Test batch logging configuration in verbose mode"""
    command = BatchCommand()
    command._configure_batch_logging(verbose=True, quiet=False)


def test_configure_batch_logging_quiet():
    """Test batch logging configuration in quiet mode"""
    import logging
    command = BatchCommand()
    command._configure_batch_logging(verbose=False, quiet=True)
    
    logger = logging.getLogger("r2inspect")
    assert logger.level == logging.CRITICAL


def test_configure_batch_logging_normal():
    """Test batch logging configuration in normal mode"""
    command = BatchCommand()
    command._configure_batch_logging(verbose=False, quiet=False)


def test_handle_error_verbose(batch_command):
    """Test error handling in verbose mode"""
    error = ValueError("Test error message")
    batch_command._handle_error(error, verbose=True)
    
    batch_command.context.logger.error.assert_called()
    batch_command.context.console.print.assert_called()


def test_handle_error_normal(batch_command):
    """Test error handling in normal mode"""
    error = RuntimeError("Test error message")
    batch_command._handle_error(error, verbose=False)
    
    batch_command.context.logger.error.assert_called()
    batch_command.context.console.print.assert_called()


def test_execute_with_config_file(batch_command, sample_batch_dir, tmp_path):
    """Test batch command execution with config file"""
    config_file = tmp_path / "config.json"
    config_file.write_text('{"key": "value"}')
    
    args = {
        "batch": str(sample_batch_dir),
        "config": str(config_file),
        "verbose": False,
        "quiet": True,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "extensions": None,
        "threads": 1
    }
    
    with patch.object(batch_command, '_run_batch_analysis'):
        with patch.object(batch_command, '_get_config', return_value=MagicMock()):
            result = batch_command.execute(args)
            assert result == 0


def test_execute_full_workflow(batch_command, sample_batch_dir, tmp_path):
    """Test complete batch command workflow"""
    output_dir = tmp_path / "output"
    
    args = {
        "batch": str(sample_batch_dir),
        "config": None,
        "yara": None,
        "xor": "test_xor",
        "output_json": True,
        "output_csv": True,
        "output": str(output_dir),
        "extensions": "exe,dll",
        "threads": 2,
        "verbose": True,
        "quiet": False
    }
    
    with patch.object(batch_command, '_run_batch_analysis'):
        result = batch_command.execute(args)
        assert result == 0
