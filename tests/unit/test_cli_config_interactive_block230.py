from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.cli import display_results
from r2inspect.cli.commands.base import CommandContext
from r2inspect.cli.commands.config_command import ConfigCommand
from r2inspect.cli.commands.interactive_command import InteractiveCommand
from r2inspect.cli.interactive import run_interactive_mode
from r2inspect.config import Config
from r2inspect.factory import create_inspector


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _fixture_path(name: str) -> Path:
    return _project_root() / "samples" / "fixtures" / name


def test_config_command_noop() -> None:
    cmd = ConfigCommand(CommandContext.create())
    assert cmd.execute({}) == 0


def test_config_command_missing_rules_dir(tmp_path: Path) -> None:
    cmd = ConfigCommand(CommandContext.create())
    missing = tmp_path / "missing_rules"
    assert cmd.execute({"list_yara": True, "yara": str(missing)}) == 1


def test_config_command_empty_rules_dir(tmp_path: Path) -> None:
    cmd = ConfigCommand(CommandContext.create())
    empty_dir = tmp_path / "rules"
    empty_dir.mkdir()
    assert cmd.execute({"list_yara": True, "yara": str(empty_dir)}) == 0


def test_config_command_lists_rules() -> None:
    cmd = ConfigCommand(CommandContext.create())
    rules_dir = _project_root() / "r2inspect" / "rules" / "yara"
    assert cmd.execute({"list_yara": True, "yara": str(rules_dir)}) == 0


def test_config_command_relative_display_fallback(tmp_path: Path) -> None:
    cmd = ConfigCommand(CommandContext.create())
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    rule_file = other_dir / "sample.yar"
    rule_file.write_text("rule dummy { condition: true }", encoding="utf-8")
    cmd._display_yara_rules_table([rule_file], rules_dir)


def test_config_command_format_file_size_gb() -> None:
    cmd = ConfigCommand(CommandContext.create())
    assert cmd._format_file_size(5 * 1024**3) == "5.0 GB"


@pytest.mark.requires_r2
def test_interactive_command_helpers_real_inspector() -> None:
    sample = _fixture_path("hello_pe.exe")
    cmd = InteractiveCommand(CommandContext.create(config=Config()))
    with create_inspector(str(sample), config=Config(), verbose=False) as inspector:
        options: dict[str, object] = {}
        cmd._cmd_info(inspector)
        cmd._cmd_pe(inspector)
        cmd._cmd_strings(inspector)
        cmd._cmd_imports(inspector)
        cmd._cmd_exports(inspector)
        cmd._cmd_sections(inspector)
        cmd._cmd_analyze(inspector, options, display_results)
        cmd._execute_interactive_command("help", inspector, options)
        cmd._execute_interactive_command("unknown", inspector, options)


def test_interactive_command_exit_checks() -> None:
    cmd = InteractiveCommand(CommandContext.create())
    assert cmd._should_exit("quit") is True
    assert cmd._should_exit("exit") is True
    assert cmd._should_exit("q") is True
    assert cmd._should_exit("continue") is False


def test_interactive_command_handle_error_paths() -> None:
    cmd = InteractiveCommand(CommandContext.create())
    cmd._handle_error(ValueError("boom"), verbose=False)
    cmd._handle_error(ValueError("boom"), verbose=True)


@pytest.mark.requires_r2
def test_run_interactive_mode_sequence(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _fixture_path("hello_pe.exe")
    commands = iter(
        [
            "help",
            "strings",
            "info",
            "pe",
            "imports",
            "exports",
            "sections",
            "analyze",
            "unknown",
            "quit",
        ]
    )
    monkeypatch.setattr("builtins.input", lambda _: next(commands))
    with create_inspector(str(sample), config=Config(), verbose=False) as inspector:
        run_interactive_mode(inspector, {})
