from __future__ import annotations

from pathlib import Path

from r2inspect.cli.commands.base import CommandContext
from r2inspect.cli.commands.batch_command import BatchCommand


def test_batch_command_helpers(tmp_path: Path):
    cmd = BatchCommand(CommandContext.create())

    recursive, auto, output = cmd._setup_batch_mode(
        str(tmp_path), None, output_json=True, output_csv=False, output=None
    )
    assert recursive is True
    assert auto is True
    assert output == "output"

    opts = cmd._setup_analysis_options(yara="rules", xor="AA")
    assert opts["custom_yara"] == "rules"
    assert opts["xor_search"] == "AA"


def test_batch_command_execute_empty_dir(tmp_path: Path):
    cmd = BatchCommand(CommandContext.create())
    exit_code = cmd.execute(
        {
            "batch": str(tmp_path),
            "config": None,
            "yara": None,
            "xor": None,
            "output_json": False,
            "output_csv": False,
            "output": None,
            "extensions": None,
            "threads": 1,
            "verbose": False,
            "quiet": False,
        }
    )
    assert exit_code == 0
