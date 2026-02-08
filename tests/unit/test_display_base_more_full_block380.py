from __future__ import annotations

from pathlib import Path

from r2inspect.cli import display_base


def test_display_base_helpers_and_branches(tmp_path: Path) -> None:
    assert display_base.format_hash_display("N/A") == "N/A"
    assert display_base.format_hash_display("x" * 40, max_length=8) == "x" * 8 + "..."
    assert display_base.format_hash_display("ok", max_length=8) == "ok"

    table = display_base.create_info_table("Info", prop_width=10, value_min_width=20)
    assert table.title == "Info"

    rules = [
        {"name": "a.yar", "size": 2048, "path": "a.yar", "relative_path": "a.yar"},
        {"name": "b.yar", "size": 512, "path": "b.yar"},
    ]
    display_base.display_yara_rules_table(rules, "rules/path")

    error_stats = {
        "total_errors": 3,
        "recent_errors": 1,
        "errors_by_category": {"file_access": 2},
        "errors_by_severity": {"critical": 1, "high": 1, "medium": 1},
        "recovery_strategies_available": 1,
    }
    display_base.display_error_statistics(error_stats)

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text("rule t { condition: true }")
    display_base.handle_list_yara_option(str(tmp_path / "config.json"), str(rules_dir))
