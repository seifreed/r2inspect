"""Comprehensive tests for batch_command.py - 100% coverage target."""

import io

from rich.console import Console

from r2inspect.cli.commands.base import CommandContext
from r2inspect.cli.commands.batch_command import BatchCommand
from r2inspect.config import Config
from r2inspect.infrastructure.logging import get_logger


def _make_console():
    return Console(file=io.StringIO(), record=True, width=120)


def _make_context(tmp_path, **kwargs):
    config = Config(str(tmp_path / "config.json"))
    return CommandContext(
        console=kwargs.get("console", _make_console()),
        logger=kwargs.get("logger", get_logger()),
        config=config,
        verbose=kwargs.get("verbose", False),
        quiet=kwargs.get("quiet", False),
    )


def test_batch_command_init(tmp_path):
    """Test BatchCommand initialization."""
    cmd = BatchCommand(_make_context(tmp_path))
    assert cmd is not None


def test_batch_command_setup_batch_mode_defaults_output(tmp_path):
    """Test _setup_batch_mode returns defaults."""
    cmd = BatchCommand(_make_context(tmp_path))
    recursive, auto_detect, output = cmd._setup_batch_mode(
        _batch="/tmp",
        extensions=None,
        output_json=True,
        output_csv=False,
        output=None,
    )
    assert recursive is True
    assert auto_detect is True
    assert output == "output"


def test_batch_command_setup_analysis_options(tmp_path):
    """Test _setup_analysis_options builds correct dict."""
    cmd = BatchCommand(_make_context(tmp_path))
    options = cmd._setup_analysis_options(yara="/rules", xor="aa")
    assert options["detect_packer"] is True
    assert options["detect_crypto"] is True
    assert options["detect_av"] is True
    assert options["full_analysis"] is True
    assert options["custom_yara"] == "/rules"
    assert options["xor_search"] == "aa"


def test_batch_command_setup_analysis_options_no_yara(tmp_path):
    """Test _setup_analysis_options without yara/xor."""
    cmd = BatchCommand(_make_context(tmp_path))
    options = cmd._setup_analysis_options(yara=None, xor=None)
    assert options["detect_packer"] is True
    assert "custom_yara" not in options or options.get("custom_yara") is None


def test_batch_command_setup_batch_mode_with_output(tmp_path):
    """Test _setup_batch_mode with custom output path."""
    cmd = BatchCommand(_make_context(tmp_path))
    recursive, auto_detect, output = cmd._setup_batch_mode(
        _batch="/tmp",
        extensions=".exe",
        output_json=False,
        output_csv=True,
        output="/custom/out",
    )
    assert output == "/custom/out"
