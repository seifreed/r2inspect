from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.cli.commands.analyze_command import AnalyzeCommand
from r2inspect.cli.commands.base import CommandContext
from r2inspect.cli.commands.batch_command import BatchCommand


def _sample_path() -> Path:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")
    return sample


def test_analyze_command_execute_json_csv(tmp_path: Path):
    sample = _sample_path()
    out_json = tmp_path / "out.json"
    out_csv = tmp_path / "out.csv"

    cmd = AnalyzeCommand(CommandContext.create())

    args_json = {
        "filename": str(sample),
        "config": None,
        "yara": None,
        "xor": None,
        "output_json": True,
        "output_csv": False,
        "output": str(out_json),
        "verbose": False,
        "threads": None,
    }
    assert cmd.execute(args_json) == 0
    assert out_json.exists()

    args_csv = dict(args_json)
    args_csv.update({"output_json": False, "output_csv": True, "output": str(out_csv)})
    assert cmd.execute(args_csv) == 0
    assert out_csv.exists()


def test_analyze_command_execute_console(tmp_path: Path):
    sample = _sample_path()
    cmd = AnalyzeCommand(CommandContext.create())

    args = {
        "filename": str(sample),
        "config": None,
        "yara": None,
        "xor": None,
        "output_json": False,
        "output_csv": False,
        "output": None,
        "verbose": False,
        "threads": None,
    }
    assert cmd.execute(args) == 0


def test_batch_command_execute(tmp_path: Path):
    sample = _sample_path()
    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()
    local_file = batch_dir / sample.name
    local_file.write_bytes(sample.read_bytes())

    cmd = BatchCommand(CommandContext.create())

    args = {
        "batch": str(batch_dir),
        "config": None,
        "yara": None,
        "xor": None,
        "output_json": True,
        "output_csv": True,
        "output": str(tmp_path / "out"),
        "extensions": "exe",
        "threads": 1,
        "verbose": False,
        "quiet": False,
    }

    assert cmd.execute(args) == 0
