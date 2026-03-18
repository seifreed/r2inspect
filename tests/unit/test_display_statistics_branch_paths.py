#!/usr/bin/env python3
"""Branch-path tests for display_statistics helper functions."""

from __future__ import annotations

import io
from dataclasses import dataclass

from rich.console import Console

from r2inspect.cli import display_statistics as stats
from r2inspect.cli.display_base import _get_console


def _make_console():
    """Create a recording console for test assertions."""
    return Console(file=io.StringIO(), record=True, width=120)


def _get_text(console: Console) -> str:
    return console.export_text()


def test_display_retry_statistics_returns_without_retries(monkeypatch) -> None:
    console = _make_console()
    monkeypatch.setattr(stats, "_get_console", lambda: console)

    stats._display_retry_statistics(
        {
            "total_retries": 0,
            "successful_retries": 0,
            "failed_after_retries": 0,
            "success_rate": 0.0,
            "commands_retried": {"cmd": 2},
        }
    )

    text = _get_text(console)
    # With total_retries == 0, the function returns early without printing
    assert "Retry" not in text


def test_display_retry_statistics_prints_and_calls_child(monkeypatch) -> None:
    console = _make_console()
    monkeypatch.setattr(stats, "_get_console", lambda: console)

    stats._display_retry_statistics(
        {
            "total_retries": 3,
            "successful_retries": 2,
            "failed_after_retries": 1,
            "success_rate": 66.6,
            "commands_retried": {"cmd_a": 2, "cmd_b": 5},
        }
    )

    text = _get_text(console)
    assert "Retry Statistics" in text
    assert "3" in text  # total retries
    assert "2" in text  # successful retries
    assert "1" in text  # failed after retries
    # _display_most_retried_commands is called as part of the real function
    assert "Most Retried Commands" in text
    assert "cmd_b" in text
    assert "cmd_a" in text


def test_display_most_retried_commands_returns_on_empty(monkeypatch) -> None:
    console = _make_console()
    monkeypatch.setattr(stats, "_get_console", lambda: console)

    stats._display_most_retried_commands({"commands_retried": {}})

    text = _get_text(console)
    assert "Most Retried" not in text


def test_display_most_retried_commands_sorts_commands(monkeypatch) -> None:
    console = _make_console()
    monkeypatch.setattr(stats, "_get_console", lambda: console)

    stats._display_most_retried_commands(
        {"commands_retried": {"cmd_low": 1, "cmd_high": 3, "cmd_mid": 2}}
    )

    text = _get_text(console)
    assert "Most Retried Commands" in text
    assert "cmd_high" in text
    assert "cmd_mid" in text
    assert "cmd_low" in text
    # Verify order: cmd_high (3) appears before cmd_low (1)
    assert text.index("cmd_high") < text.index("cmd_low")


def test_display_circuit_breaker_statistics_returns_on_empty_stats(monkeypatch) -> None:
    console = _make_console()
    monkeypatch.setattr(stats, "_get_console", lambda: console)

    stats._display_circuit_breaker_statistics({})

    text = _get_text(console)
    assert "Circuit" not in text


def test_display_circuit_breaker_statistics_returns_when_no_positive_metrics(monkeypatch) -> None:
    console = _make_console()
    monkeypatch.setattr(stats, "_get_console", lambda: console)

    stats._display_circuit_breaker_statistics({"total_failures": 0, "state": "closed"})

    text = _get_text(console)
    assert "Circuit" not in text


def test_display_circuit_breaker_statistics_prints_positive_metrics(monkeypatch) -> None:
    console = _make_console()
    monkeypatch.setattr(stats, "_get_console", lambda: console)

    stats._display_circuit_breaker_statistics(
        {
            "total_failures": 4,
            "success_rate": 0.0,
            "open_circuits": 2,
        }
    )

    text = _get_text(console)
    assert "Circuit Breaker Statistics" in text
    assert "Total Failures" in text
    assert "4" in text
    assert "Open Circuits" in text
    assert "2" in text
