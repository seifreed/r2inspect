from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from r2inspect import cli_main


def _sample_path() -> Path:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")
    return sample


def _base_args() -> dict[str, object]:
    return {
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
        "threads": 1,
        "version": False,
    }


@pytest.mark.unit
def test_run_cli_version_exits_zero() -> None:
    args = cli_main.CLIArgs(**{**_base_args(), "version": True})
    with pytest.raises(SystemExit) as exc:
        cli_main.run_cli(args)
    assert exc.value.code == 0


@pytest.mark.unit
def test_run_cli_list_yara_exits_zero(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "demo.yar").write_text("rule demo { condition: true }")

    sample = _sample_path()
    args = cli_main.CLIArgs(
        **{
            **_base_args(),
            "filename": str(sample),
            "list_yara": True,
            "yara": str(rules_dir),
        }
    )
    with pytest.raises(SystemExit) as exc:
        cli_main.run_cli(args)
    assert exc.value.code == 0


@pytest.mark.unit
def test_run_cli_interactive_exit_zero() -> None:
    sample = _sample_path()
    args = cli_main.CLIArgs(
        **{
            **_base_args(),
            "filename": str(sample),
            "interactive": True,
            "quiet": False,
        }
    )
    original_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO("help\nunknown\nquit\n")
        with pytest.raises(SystemExit) as exc:
            cli_main.run_cli(args)
        assert exc.value.code == 0
    finally:
        sys.stdin = original_stdin


@pytest.mark.unit
def test_run_cli_batch_exit_zero(tmp_path: Path) -> None:
    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()
    sample = _sample_path()
    target = batch_dir / sample.name
    target.write_bytes(sample.read_bytes())

    args = cli_main.CLIArgs(
        **{
            **_base_args(),
            "batch": str(batch_dir),
            "output_csv": True,
            "output": str(tmp_path / "out"),
            "quiet": True,
        }
    )
    with pytest.raises(SystemExit) as exc:
        cli_main.run_cli(args)
    assert exc.value.code == 0


@pytest.mark.unit
def test_run_cli_analyze_exit_zero() -> None:
    sample = _sample_path()
    args = cli_main.CLIArgs(
        **{
            **_base_args(),
            "filename": str(sample),
            "output_json": True,
            "quiet": True,
        }
    )
    with pytest.raises(SystemExit) as exc:
        cli_main.run_cli(args)
    assert exc.value.code == 0
