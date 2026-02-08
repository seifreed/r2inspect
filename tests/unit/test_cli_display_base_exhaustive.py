from __future__ import annotations

from pathlib import Path

from r2inspect.cli import display_base


def test_display_base_helpers(tmp_path: Path) -> None:
    assert display_base.format_hash_display(None) == "N/A"
    long_hash = "a" * 64
    assert display_base.format_hash_display(long_hash, max_length=8) == "aaaaaaaa..."

    table = display_base.create_info_table("Info")
    assert table.title == "Info"

    display_base.display_validation_errors(["bad input"])


def test_display_yara_rules_table_and_list(tmp_path: Path) -> None:
    rules = [{"name": "rule1.yar", "size": 1024, "path": "/tmp/rule1.yar"}]
    display_base.display_yara_rules_table(rules, "/tmp")

    config_path = tmp_path / "config.json"
    display_base.handle_list_yara_option(str(config_path), yara=str(tmp_path / "rules"))
