#!/usr/bin/env python3
"""Display helpers for performance statistics."""

from __future__ import annotations

from typing import Any

from rich.table import Table

from .display_base import _get_console


def _display_retry_statistics(retry_stats: dict[str, Any]) -> None:
    """Display retry statistics table"""
    if retry_stats["total_retries"] <= 0:
        return

    retry_table = Table(title="Retry Statistics", show_header=True)
    retry_table.add_column("Metric", style="cyan")
    retry_table.add_column("Value", style="green")

    retry_table.add_row("Total Retries", str(retry_stats["total_retries"]))
    retry_table.add_row("Successful Retries", str(retry_stats["successful_retries"]))
    retry_table.add_row("Failed After Retries", str(retry_stats["failed_after_retries"]))
    retry_table.add_row("Success Rate", f"{retry_stats['success_rate']:.1f}%")

    _get_console().print(retry_table)
    _display_most_retried_commands(retry_stats)


def _display_most_retried_commands(retry_stats: dict[str, Any]) -> None:
    """Display table of most retried commands"""
    if not retry_stats["commands_retried"]:
        return

    cmd_table = Table(title="Most Retried Commands", show_header=True)
    cmd_table.add_column("Command", style="cyan")
    cmd_table.add_column("Retry Count", style="yellow")

    sorted_commands = sorted(
        retry_stats["commands_retried"].items(),
        key=lambda x: x[1],
        reverse=True,
    )[:5]

    for command, count in sorted_commands:
        cmd_table.add_row(command, str(count))

    _get_console().print(cmd_table)


def _display_circuit_breaker_statistics(circuit_stats: dict[str, Any]) -> None:
    """Display circuit breaker statistics table"""
    if not circuit_stats:
        return

    cb_entries = []
    for metric, value in circuit_stats.items():
        if isinstance(value, int | float) and value > 0:
            cb_entries.append((metric, value))

    if not cb_entries:
        return

    cb_table = Table(title="Circuit Breaker Statistics", show_header=True)
    cb_table.add_column("Metric", style="cyan")
    cb_table.add_column("Value", style="green")

    for metric, value in cb_entries:
        cb_table.add_row(metric.replace("_", " ").title(), str(value))

    _get_console().print(cb_table)
