from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from r2inspect import cli_main


def _sample_path() -> Path:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")
    return sample


@pytest.mark.unit
def test_click_cli_version() -> None:
    runner = CliRunner()
    result = runner.invoke(cli_main.cli, ["--version"])
    assert result.exit_code == 0


@pytest.mark.unit
def test_click_cli_list_yara(tmp_path: Path) -> None:
    sample = _sample_path()
    runner = CliRunner()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "demo.yar").write_text("rule demo { condition: true }")
    result = runner.invoke(
        cli_main.cli,
        ["--list-yara", "--yara", str(rules_dir), str(sample)],
    )
    assert result.exit_code == 0


@pytest.mark.unit
def test_click_cli_interactive_quit() -> None:
    sample = _sample_path()
    runner = CliRunner()
    result = runner.invoke(cli_main.cli, ["--interactive", str(sample)], input="quit\n")
    assert result.exit_code == 0
