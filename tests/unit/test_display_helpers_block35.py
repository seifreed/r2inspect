from __future__ import annotations

from r2inspect.cli.display import (
    _display_most_retried_commands,
    _display_retry_statistics,
    create_info_table,
    display_error_statistics,
    display_validation_errors,
    format_hash_display,
)


def test_format_hash_display():
    assert format_hash_display(None) == "N/A"
    assert format_hash_display("N/A") == "N/A"
    assert format_hash_display("abcd", max_length=3) == "abc..."
    assert format_hash_display("abcd", max_length=10) == "abcd"


def test_create_info_table():
    table = create_info_table("Title", prop_width=10, value_min_width=20)
    assert table.title == "Title"


def test_display_validation_errors(capsys):
    display_validation_errors(["err1", "err2"])
    out = capsys.readouterr().out
    assert "err1" in out and "err2" in out


def test_display_error_statistics(capsys):
    stats = {
        "total_errors": 2,
        "recent_errors": 1,
        "recovery_strategies_available": 1,
        "errors_by_category": {"file_access": 1},
        "errors_by_severity": {"high": 2},
    }
    display_error_statistics(stats)
    out = capsys.readouterr().out
    assert "Error Statistics" in out
    assert "Total Errors" in out


def test_retry_tables(capsys):
    retry_stats = {
        "total_retries": 2,
        "successful_retries": 1,
        "failed_after_retries": 1,
        "success_rate": 50.0,
        "commands_retried": {"pd 10": 2},
    }
    _display_retry_statistics(retry_stats)
    _display_most_retried_commands(retry_stats)
    out = capsys.readouterr().out
    assert "Retry Statistics" in out
    assert "Most Retried Commands" in out
