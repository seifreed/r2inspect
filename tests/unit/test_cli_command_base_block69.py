from __future__ import annotations

from pathlib import Path

from r2inspect.cli.commands.base import Command, CommandContext, apply_thread_settings
from r2inspect.config import Config


class _DummyCommand(Command):
    def run(self, *args, **kwargs):
        return 0

    def execute(self, *args, **kwargs):
        return 0


def test_command_context_property_and_config(tmp_path: Path):
    config_path = tmp_path / "config.json"
    config = Config(str(config_path))
    context = CommandContext.create(config=config, verbose=True, quiet=False, thread_safe=True)

    cmd = _DummyCommand()
    assert cmd.context is not None

    cmd.context = context
    assert cmd.context.config is config


def test_apply_thread_settings_updates_config(tmp_path: Path):
    config_path = tmp_path / "config.json"
    config = Config(str(config_path))

    apply_thread_settings(config, 8)
    assert config.typed_config.pipeline.max_workers == 8
    assert config.typed_config.pipeline.parallel_execution is True

    # Invalid threads should not crash or change config
    apply_thread_settings(config, "bad")
    assert config.typed_config.pipeline.max_workers == 8
