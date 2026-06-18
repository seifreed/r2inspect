#!/usr/bin/env python3
"""Display helpers for performance statistics."""

from __future__ import annotations

from typing import Any

from rich.table import Table

from .display_base import _get_console


def _coerce_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _display_retry_statistics(retry_stats: dict[str, Any]) -> None:
    """Display retry statistics table"""
    if not isinstance(retry_stats, dict):
        return

    if _coerce_float(retry_stats.get("total_retries", 0)) <= 0:
        return

    retry_table = Table(title="Retry Statistics", show_header=True)
    retry_table.add_column("Metric", style="cyan")
    retry_table.add_column("Value", style="green")

    total_retries = retry_stats.get("total_retries", 0)
    successful_retries = retry_stats.get("successful_retries", 0)
    failed_after_retries = retry_stats.get("failed_after_retries", 0)
    success_rate = retry_stats.get("success_rate", 0.0)

    retry_table.add_row("Total Retries", str(total_retries))
    retry_table.add_row("Successful Retries", str(successful_retries))
    retry_table.add_row("Failed After Retries", str(failed_after_retries))
    success_rate_text = f"{_coerce_float(success_rate):.1f}%"
    retry_table.add_row("Success Rate", success_rate_text)

    _get_console().print(retry_table)
    _display_most_retried_commands(retry_stats)


def _display_most_retried_commands(retry_stats: dict[str, Any]) -> None:
    """Display table of most retried commands"""
    if not isinstance(retry_stats, dict):
        return

    commands_retried = retry_stats.get("commands_retried", {})
    if not isinstance(commands_retried, dict) or not commands_retried:
        return

    cmd_table = Table(title="Most Retried Commands", show_header=True)
    cmd_table.add_column("Command", style="cyan")
    cmd_table.add_column("Retry Count", style="yellow")

    sorted_commands = sorted(
        commands_retried.items(),
        key=lambda x: _coerce_float(x[1]),
        reverse=True,
    )[:5]

    for command, count in sorted_commands:
        cmd_table.add_row(command, str(count))

    _get_console().print(cmd_table)


def _display_circuit_breaker_statistics(circuit_stats: dict[str, Any]) -> None:
    """Display circuit breaker statistics table"""
    if not isinstance(circuit_stats, dict) or not circuit_stats:
        return

    cb_entries = []
    for metric, value in circuit_stats.items():
        coerced_value = _coerce_float(value)
        if coerced_value > 0:
            cb_entries.append((metric, coerced_value))

    if not cb_entries:
        return

    cb_table = Table(title="Circuit Breaker Statistics", show_header=True)
    cb_table.add_column("Metric", style="cyan")
    cb_table.add_column("Value", style="green")

    for metric, value in cb_entries:
        cb_table.add_row(metric.replace("_", " ").title(), str(value))

    _get_console().print(cb_table)
