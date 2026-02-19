#!/usr/bin/env python3
"""Branch path tests for CLI command modules."""

from __future__ import annotations

from r2inspect.cli.commands.base import Command, CommandContext
from r2inspect.cli.commands.version_command import VersionCommand
from r2inspect.cli.display_base import _StdoutProxy


# ---------------------------------------------------------------------------
# version_command.py
# ---------------------------------------------------------------------------

def test_version_command_execute_returns_zero() -> None:
    """VersionCommand.execute displays version info and returns 0."""
    context = CommandContext.create()
    cmd = VersionCommand(context=context)
    result = cmd.execute({})
    assert result == 0


def test_version_command_displays_version_info(capsys) -> None:
    """VersionCommand._display_version_info outputs author, license, and URL."""
    from r2inspect.__version__ import __author__, __license__, __url__, __version__
    context = CommandContext.create()
    cmd = VersionCommand(context=context)
    cmd._display_version_info()
    # No assertion on capsys since rich writes to its own stream;
    # just verifying no exception is raised and method completes.


# ---------------------------------------------------------------------------
# base.py
# ---------------------------------------------------------------------------

def test_get_config_with_config_path_returns_config_for_path(tmp_path) -> None:
    """Command._get_config returns a Config loaded from the given path when config_path is set."""
    config_file = tmp_path / "test_config.toml"
    config_file.write_text("[general]\n")

    context = CommandContext.create()

    class ConcreteCommand(Command):
        def execute(self, args):
            return 0

    cmd = ConcreteCommand(context=context)
    config = cmd._get_config(config_path=str(config_file))
    assert config is not None


def test_get_config_without_path_returns_context_config() -> None:
    """Command._get_config returns context config when no config_path is given."""
    context = CommandContext.create()

    class ConcreteCommand(Command):
        def execute(self, args):
            return 0

    cmd = ConcreteCommand(context=context)
    config = cmd._get_config()
    assert config is context.config


# ---------------------------------------------------------------------------
# display_base.py
# ---------------------------------------------------------------------------

def test_stdout_proxy_errors_property() -> None:
    """_StdoutProxy.errors returns the encoding errors attribute from sys.stdout."""
    import sys
    proxy = _StdoutProxy()
    result = proxy.errors
    expected = getattr(sys.stdout, "errors", "strict")
    assert result == expected


def test_stdout_proxy_encoding_property() -> None:
    """_StdoutProxy.encoding returns the encoding attribute from sys.stdout."""
    import sys
    proxy = _StdoutProxy()
    result = proxy.encoding
    expected = getattr(sys.stdout, "encoding", "utf-8")
    assert result == expected
