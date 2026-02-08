from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

import r2inspect.cli as cli
from r2inspect.cli import display_base
from r2inspect.config import Config


def test_cli_lazy_exports_and_dir() -> None:
    importlib.reload(cli)
    assert callable(cli.setup_rate_limiter)
    assert callable(cli.display_results)
    assert "validators" in cli.__dir__()

    with pytest.raises(AttributeError):
        _ = cli.__getattr__("missing")


def test_cli_main_version_exit() -> None:
    argv = sys.argv[:]
    try:
        sys.argv = ["r2inspect", "--version"]
        with pytest.raises(SystemExit):
            cli.main()
    finally:
        sys.argv = argv


def test_display_base_banner_and_tables(tmp_path: Path) -> None:
    original_pyfiglet = display_base.pyfiglet
    try:
        display_base.pyfiglet = None
        display_base.print_banner()
    finally:
        display_base.pyfiglet = original_pyfiglet

    table = display_base.create_info_table("Test Table")
    assert table.title == "Test Table"

    assert display_base.format_hash_display("abcd", max_length=2) == "ab..."
    assert display_base.format_hash_display("") == "N/A"

    error_stats = {
        "total_errors": 2,
        "recent_errors": 1,
        "recovery_strategies_available": 1,
        "errors_by_category": {"file_access": 2},
        "errors_by_severity": {"critical": 1, "high": 1, "medium": 1},
    }
    display_base.display_error_statistics(error_stats)
    display_base.display_validation_errors(["bad input"])

    display_base.display_performance_statistics(
        {
            "total_retries": 1,
            "successful_retries": 1,
            "failed_after_retries": 0,
            "success_rate": 100.0,
            "commands_retried": {},
            "error_types_retried": {},
        },
        {"breaker_test": {"state": "open", "failure_count": 1}},
    )


def test_display_base_list_yara_option(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "sample.yar").write_text("rule test { condition: true }", encoding="utf-8")

    config_path = str(tmp_path / "r2inspect_config.json")
    _ = Config(config_path)
    display_base.handle_list_yara_option(config_path, str(rules_dir))

    empty_dir = tmp_path / "empty_rules"
    empty_dir.mkdir()
    display_base.handle_list_yara_option(config_path, str(empty_dir))
