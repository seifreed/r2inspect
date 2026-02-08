from __future__ import annotations

from r2inspect.cli.commands.base import CommandContext
from r2inspect.cli.commands.config_command import ConfigCommand


def test_config_command_noop(capsys):
    cmd = ConfigCommand(CommandContext.create())
    exit_code = cmd.execute({"list_yara": False})
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "No configuration operation" in out
