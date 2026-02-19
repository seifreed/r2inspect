#!/usr/bin/env python3
"""Branch-path tests for r2inspect/cli/commands/config_command.py.

Covers missing lines: 62-63, 69-70, 90, 93, 95-97, 100, 102-104,
107-108, 122, 124-125, 127, 141-144, 146, 148-149, 152, 155-163,
175-180.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.cli.commands.base import CommandContext
from r2inspect.cli.commands.config_command import ConfigCommand


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_command() -> ConfigCommand:
    return ConfigCommand(CommandContext.create())


# ---------------------------------------------------------------------------
# execute – list_yara=True branch (lines 62-63)
# ---------------------------------------------------------------------------


def test_execute_list_yara_true_with_nonexistent_path(tmp_path: Path):
    cmd = make_command()
    nonexistent = str(tmp_path / "no_such_dir")
    exit_code = cmd.execute({"list_yara": True, "yara": nonexistent})
    assert exit_code == 1


def test_execute_list_yara_false_prints_message(capsys):
    cmd = make_command()
    exit_code = cmd.execute({"list_yara": False})
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "No configuration operation" in out


# ---------------------------------------------------------------------------
# _list_yara_rules – directory does not exist (lines 95-97)
# ---------------------------------------------------------------------------


def test_list_yara_rules_path_does_not_exist(tmp_path: Path):
    cmd = make_command()
    missing_dir = str(tmp_path / "missing")
    exit_code = cmd._list_yara_rules(yara_path=missing_dir)
    assert exit_code == 1


# ---------------------------------------------------------------------------
# _list_yara_rules – directory exists but contains no YARA files (lines 102-104)
# ---------------------------------------------------------------------------


def test_list_yara_rules_directory_empty(tmp_path: Path):
    cmd = make_command()
    empty_dir = tmp_path / "yara_empty"
    empty_dir.mkdir()
    exit_code = cmd._list_yara_rules(yara_path=str(empty_dir))
    assert exit_code == 0


def test_list_yara_rules_directory_has_non_yara_files(tmp_path: Path):
    cmd = make_command()
    yara_dir = tmp_path / "yara_dir"
    yara_dir.mkdir()
    (yara_dir / "readme.txt").write_text("not a yara file")
    exit_code = cmd._list_yara_rules(yara_path=str(yara_dir))
    assert exit_code == 0


# ---------------------------------------------------------------------------
# _list_yara_rules – directory has YARA files → display table (lines 107-108)
# ---------------------------------------------------------------------------


def test_list_yara_rules_with_yar_files_returns_zero(tmp_path: Path):
    cmd = make_command()
    yara_dir = tmp_path / "rules"
    yara_dir.mkdir()
    (yara_dir / "test_rule.yar").write_text('rule test { condition: true }')
    exit_code = cmd._list_yara_rules(yara_path=str(yara_dir))
    assert exit_code == 0


def test_list_yara_rules_with_yara_extension_files(tmp_path: Path):
    cmd = make_command()
    yara_dir = tmp_path / "rules"
    yara_dir.mkdir()
    (yara_dir / "detect.yara").write_text('rule detect { condition: true }')
    exit_code = cmd._list_yara_rules(yara_path=str(yara_dir))
    assert exit_code == 0


# ---------------------------------------------------------------------------
# _find_yara_rules (lines 122, 124-125, 127)
# ---------------------------------------------------------------------------


def test_find_yara_rules_finds_yar_files(tmp_path: Path):
    cmd = make_command()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "rule_a.yar").write_text('rule a { condition: true }')
    (rules_dir / "rule_b.yara").write_text('rule b { condition: true }')
    found = cmd._find_yara_rules(rules_dir)
    names = [f.name for f in found]
    assert "rule_a.yar" in names
    assert "rule_b.yara" in names


def test_find_yara_rules_recursive_search(tmp_path: Path):
    cmd = make_command()
    rules_dir = tmp_path / "rules"
    subdir = rules_dir / "malware"
    subdir.mkdir(parents=True)
    (subdir / "nested.yar").write_text('rule nested { condition: true }')
    found = cmd._find_yara_rules(rules_dir)
    assert any("nested.yar" in str(f) for f in found)


def test_find_yara_rules_empty_directory(tmp_path: Path):
    cmd = make_command()
    rules_dir = tmp_path / "empty_rules"
    rules_dir.mkdir()
    found = cmd._find_yara_rules(rules_dir)
    assert found == []


def test_find_yara_rules_returns_sorted_list(tmp_path: Path):
    cmd = make_command()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "zzz.yar").write_text('rule z { condition: true }')
    (rules_dir / "aaa.yar").write_text('rule a { condition: true }')
    found = cmd._find_yara_rules(rules_dir)
    names = [f.name for f in found]
    assert names == sorted(names)


# ---------------------------------------------------------------------------
# _display_yara_rules_table (lines 141-163)
# ---------------------------------------------------------------------------


def test_display_yara_rules_table_runs_without_error(tmp_path: Path, capsys):
    cmd = make_command()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_file = rules_dir / "my_rule.yar"
    rule_file.write_text('rule my_rule { condition: true }')
    cmd._display_yara_rules_table([rule_file], rules_dir)
    out = capsys.readouterr().out
    assert "my_rule.yar" in out


def test_display_yara_rules_table_category_root_when_file_at_top_level(
    tmp_path: Path, capsys
):
    cmd = make_command()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_file = rules_dir / "top_level.yar"
    rule_file.write_text('rule top { condition: true }')
    cmd._display_yara_rules_table([rule_file], rules_dir)
    out = capsys.readouterr().out
    assert "Root" in out


def test_display_yara_rules_table_category_from_subdirectory(tmp_path: Path, capsys):
    cmd = make_command()
    rules_dir = tmp_path / "rules"
    sub = rules_dir / "ransomware"
    sub.mkdir(parents=True)
    rule_file = sub / "detect.yar"
    rule_file.write_text('rule r { condition: true }')
    cmd._display_yara_rules_table([rule_file], rules_dir)
    out = capsys.readouterr().out
    assert "ransomware" in out


def test_display_yara_rules_table_shows_rules_directory(tmp_path: Path, capsys):
    cmd = make_command()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_file = rules_dir / "rule.yar"
    rule_file.write_text('rule r { condition: true }')
    cmd._display_yara_rules_table([rule_file], rules_dir)
    out = capsys.readouterr().out
    assert "Rules directory" in out


# ---------------------------------------------------------------------------
# _format_file_size (lines 175-180)
# ---------------------------------------------------------------------------


def test_format_file_size_bytes_range():
    cmd = make_command()
    result = cmd._format_file_size(500)
    assert "B" in result
    assert "500.0" in result


def test_format_file_size_kilobytes_range():
    cmd = make_command()
    result = cmd._format_file_size(2048)
    assert "KB" in result


def test_format_file_size_megabytes_range():
    cmd = make_command()
    result = cmd._format_file_size(2 * 1024 * 1024)
    assert "MB" in result


def test_format_file_size_gigabytes_range():
    cmd = make_command()
    result = cmd._format_file_size(2 * 1024 * 1024 * 1024)
    assert "GB" in result


# ---------------------------------------------------------------------------
# execute – with list_yara=True using config_path (line 93 with config)
# ---------------------------------------------------------------------------


def test_execute_list_yara_with_explicit_yara_path_that_exists(tmp_path: Path):
    cmd = make_command()
    yara_dir = tmp_path / "custom_rules"
    yara_dir.mkdir()
    (yara_dir / "custom.yar").write_text('rule c { condition: true }')
    exit_code = cmd.execute({"list_yara": True, "yara": str(yara_dir)})
    assert exit_code == 0
