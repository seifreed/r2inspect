import io
from pathlib import Path

import pytest
from rich.console import Console

from r2inspect.cli.commands.base import CommandContext
from r2inspect.cli_main import CLIArgs, _dispatch_command, run_cli
from r2inspect.config import Config
from r2inspect.utils.logger import get_logger


def _make_console():
    return Console(file=io.StringIO(), record=True, width=120)


def _make_args(**overrides):
    base = {
        "filename": None,
        "interactive": False,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "xor": None,
        "verbose": False,
        "quiet": True,
        "config": None,
        "yara": None,
        "batch": None,
        "extensions": None,
        "list_yara": False,
        "threads": 10,
        "version": False,
    }
    base.update(overrides)
    return CLIArgs(**base)


def test_run_cli_validation_errors_exit(tmp_path):
    args = _make_args(filename=str(tmp_path / "missing.bin"))
    with pytest.raises(SystemExit) as exc:
        run_cli(args)
    assert exc.value.code == 1


def test_run_cli_list_yara_exits(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "sample.yar").write_text("rule sample {}")

    config_path = tmp_path / "config.json"
    config_path.write_text("{}")
    args = _make_args(list_yara=True, yara=str(rules_dir), config=str(config_path))

    with pytest.raises(SystemExit) as exc:
        run_cli(args)
    assert exc.value.code == 0


def test_run_cli_version_exits(tmp_path):
    args = _make_args(version=True)
    with pytest.raises(SystemExit) as exc:
        run_cli(args)
    assert exc.value.code == 0


def test_dispatch_command_batch_exits_zero(tmp_path):
    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()

    config = Config(str(tmp_path / "config.json"))
    context = CommandContext(
        console=_make_console(),
        logger=get_logger(),
        config=config,
        verbose=False,
        quiet=True,
    )

    args = _make_args(batch=str(batch_dir), extensions="txt", quiet=True)
    with pytest.raises(SystemExit) as exc:
        _dispatch_command(context, args)
    assert exc.value.code == 0
