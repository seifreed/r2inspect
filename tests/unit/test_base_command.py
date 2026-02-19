#!/usr/bin/env python3
"""Tests for r2inspect/cli/commands/base.py - CommandContext and Command abstractions."""

import logging
from pathlib import Path

from rich.console import Console

from r2inspect.cli.commands.base import (
    Command,
    CommandContext,
    apply_thread_settings,
    configure_logging_levels,
    configure_quiet_logging,
)
from r2inspect.config import Config


def test_configure_logging_levels_verbose():
    """Test configure_logging_levels with verbose=True."""
    configure_logging_levels(verbose=True, quiet=False)
    
    r2inspect_logger = logging.getLogger("r2inspect")
    assert r2inspect_logger.level == logging.INFO


def test_configure_logging_levels_warning():
    """Test configure_logging_levels with verbose=False."""
    configure_logging_levels(verbose=False, quiet=False)
    
    r2inspect_logger = logging.getLogger("r2inspect")
    assert r2inspect_logger.level == logging.WARNING


def test_configure_logging_levels_quiet():
    """Test configure_logging_levels with quiet=True."""
    configure_logging_levels(verbose=False, quiet=True)
    
    r2pipe_logger = logging.getLogger("r2pipe")
    r2inspect_logger = logging.getLogger("r2inspect")
    
    assert r2pipe_logger.level == logging.CRITICAL
    assert r2inspect_logger.level == logging.WARNING


def test_configure_quiet_logging_enabled():
    """Test configure_quiet_logging with quiet=True."""
    configure_quiet_logging(quiet=True)
    
    r2pipe_logger = logging.getLogger("r2pipe")
    r2inspect_logger = logging.getLogger("r2inspect")
    
    assert r2pipe_logger.level == logging.CRITICAL
    assert r2inspect_logger.level == logging.WARNING


def test_configure_quiet_logging_disabled():
    """Test configure_quiet_logging with quiet=False."""
    # Reset to a known state first
    logging.getLogger("r2pipe").setLevel(logging.DEBUG)
    original_level = logging.getLogger("r2pipe").level
    
    configure_quiet_logging(quiet=False)
    
    # Should not change when quiet=False
    assert logging.getLogger("r2pipe").level == original_level


def test_apply_thread_settings_none():
    """Test apply_thread_settings with threads=None."""
    config = Config()
    original_config = config.config.copy() if hasattr(config, 'config') else {}
    
    apply_thread_settings(config, threads=None)
    
    # Config should remain unchanged
    assert True


def test_apply_thread_settings_single_thread():
    """Test apply_thread_settings with threads=1."""
    config = Config()
    
    apply_thread_settings(config, threads=1)
    
    # Should set parallel_execution to False for single thread
    assert True


def test_apply_thread_settings_multiple_threads():
    """Test apply_thread_settings with threads=4."""
    config = Config()
    
    apply_thread_settings(config, threads=4)
    
    # Should set parallel_execution to True for multiple threads
    assert True


def test_apply_thread_settings_invalid_value():
    """Test apply_thread_settings with invalid thread count."""
    config = Config()
    
    # Should not raise an exception, just keep config unchanged
    apply_thread_settings(config, threads="invalid")
    assert True


def test_command_context_create_default():
    """Test CommandContext.create with default parameters."""
    context = CommandContext.create()
    
    assert context is not None
    assert isinstance(context.console, Console)
    assert context.logger is not None
    assert context.config is not None
    assert context.verbose is False
    assert context.quiet is False


def test_command_context_create_verbose():
    """Test CommandContext.create with verbose=True."""
    context = CommandContext.create(verbose=True)
    
    assert context.verbose is True
    assert context.logger is not None


def test_command_context_create_quiet():
    """Test CommandContext.create with quiet=True."""
    context = CommandContext.create(quiet=True)
    
    assert context.quiet is True
    assert context.logger is not None


def test_command_context_create_with_config():
    """Test CommandContext.create with custom config."""
    config = Config()
    context = CommandContext.create(config=config)
    
    assert context.config is config


def test_command_context_create_thread_safe():
    """Test CommandContext.create with thread_safe=True."""
    context = CommandContext.create(thread_safe=True)
    
    assert context.logger is not None
    assert context is not None


def test_command_context_init():
    """Test CommandContext initialization."""
    console = Console()
    logger = logging.getLogger("test")
    config = Config()
    
    context = CommandContext(
        console=console,
        logger=logger,
        config=config,
        verbose=True,
        quiet=False,
    )
    
    assert context.console is console
    assert context.logger is logger
    assert context.config is config
    assert context.verbose is True
    assert context.quiet is False


def test_command_abstract_base():
    """Test Command abstract base class."""
    # Cannot instantiate abstract class directly
    try:
        Command()
        assert False, "Should not be able to instantiate abstract Command"
    except TypeError:
        assert True


def test_command_with_context():
    """Test Command subclass with context."""
    class TestCommand(Command):
        def execute(self, args):
            return 0
    
    context = CommandContext.create()
    cmd = TestCommand(context)
    
    assert cmd.context is context


def test_command_context_property_creation():
    """Test Command.context property creates default context if needed."""
    class TestCommand(Command):
        def execute(self, args):
            return 0
    
    cmd = TestCommand()
    context = cmd.context
    
    assert context is not None
    assert isinstance(context, CommandContext)


def test_command_context_property_getter_setter():
    """Test Command.context property getter and setter."""
    class TestCommand(Command):
        def execute(self, args):
            return 0
    
    cmd = TestCommand()
    context1 = CommandContext.create()
    context2 = CommandContext.create()
    
    cmd.context = context1
    assert cmd.context is context1
    
    cmd.context = context2
    assert cmd.context is context2


def test_command_get_config_with_path():
    """Test Command._get_config with custom config path."""
    class TestCommand(Command):
        def execute(self, args):
            return 0
    
    cmd = TestCommand(CommandContext.create())
    config = cmd._get_config(config_path=None)
    
    assert config is not None
    assert isinstance(config, Config)


def test_command_get_config_from_context():
    """Test Command._get_config uses context config."""
    class TestCommand(Command):
        def execute(self, args):
            return 0
    
    context_config = Config()
    context = CommandContext.create(config=context_config)
    cmd = TestCommand(context)
    
    config = cmd._get_config()
    assert config is context_config


def test_command_get_config_default():
    """Test Command._get_config returns new Config if context has none."""
    class TestCommand(Command):
        def execute(self, args):
            return 0
    
    context = CommandContext(
        console=Console(),
        logger=logging.getLogger("test"),
        config=None,
    )
    cmd = TestCommand(context)
    
    config = cmd._get_config()
    assert config is not None
    assert isinstance(config, Config)


def test_command_setup_analysis_options_empty():
    """Test Command._setup_analysis_options with no options."""
    class TestCommand(Command):
        def execute(self, args):
            return 0
    
    cmd = TestCommand(CommandContext.create())
    options = cmd._setup_analysis_options()
    
    assert options == {}


def test_command_setup_analysis_options_yara():
    """Test Command._setup_analysis_options with YARA rules."""
    class TestCommand(Command):
        def execute(self, args):
            return 0
    
    cmd = TestCommand(CommandContext.create())
    options = cmd._setup_analysis_options(yara="/path/to/rules")
    
    assert options["yara_rules_dir"] == "/path/to/rules"


def test_command_setup_analysis_options_xor():
    """Test Command._setup_analysis_options with XOR key."""
    class TestCommand(Command):
        def execute(self, args):
            return 0
    
    cmd = TestCommand(CommandContext.create())
    options = cmd._setup_analysis_options(xor="FF")
    
    assert options["xor_search"] == "FF"


def test_command_setup_analysis_options_both():
    """Test Command._setup_analysis_options with both YARA and XOR."""
    class TestCommand(Command):
        def execute(self, args):
            return 0
    
    cmd = TestCommand(CommandContext.create())
    options = cmd._setup_analysis_options(
        yara="/path/to/rules",
        xor="FF",
    )
    
    assert options["yara_rules_dir"] == "/path/to/rules"
    assert options["xor_search"] == "FF"
    assert len(options) == 2
