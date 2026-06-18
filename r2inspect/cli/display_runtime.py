#!/usr/bin/env python3
"""Shared runtime helpers for display facades."""

from __future__ import annotations

import inspect
from typing import Any

from rich.table import Table


def print_banner(*, get_console: Any, pyfiglet: Any) -> None:
    try:
        if pyfiglet is not None:
            banner = pyfiglet.figlet_format("r2inspect", font="slant")
            get_console().print(f"[bold blue]{banner}[/bold blue]")
        else:
            get_console().print("[bold blue]r2inspect[/bold blue]")
        get_console().print("[bold]Advanced Malware Analysis Tool using Radare2[/bold]")
        get_console().print("[dim]Professional malware analysis powered by radare2[/dim]\n")
    except Exception:
        print("r2inspect - Advanced Malware Analysis Tool using Radare2")
        print("Professional malware analysis powered by radare2")
        print()


def display_yara_rules_table(
    available_rules: list[dict[str, Any]],
    rules_path: str,
    *,
    get_console: Any,
) -> None:
    def _coerce_text(value: Any, default: str) -> str:
        return value if isinstance(value, str) and value else default

    table = Table(title=f"Available YARA Rules in: {rules_path}")
    table.add_column("Rule File", style="cyan")
    table.add_column("Size", style="yellow")
    table.add_column("Path", style="green")

    for rule in available_rules:
        if not isinstance(rule, dict):
            continue
        size = rule.get("size", 0)
        try:
            size_kb = float(size) / 1024
        except (TypeError, ValueError):
            size_kb = 0.0
        rule_name = _coerce_text(rule.get("name"), "unknown")
        path = _coerce_text(rule.get("relative_path"), _coerce_text(rule.get("path"), rule_name))
        table.add_row(
            rule_name,
            f"{size_kb:.1f} KB",
            str(path),
        )

    get_console().print(table)
    get_console().print(f"\n[green]Total: {len(available_rules)} YARA rule file(s) found[/green]")
    get_console().print(
        "[blue]All these files will be automatically loaded when running analysis[/blue]"
    )


def handle_list_yara_option(
    config: Any,
    yara: str | None,
    *,
    config_cls: Any,
    display_yara_rules_table: Any,
    get_console: Any,
    yara_analyzer_cls: Any | None = None,
) -> None:
    if yara_analyzer_cls is None:
        from ..modules.yara_analyzer import YaraAnalyzer

        yara_analyzer_cls = YaraAnalyzer

    config_obj = config_cls(config)

    class DummyR2:
        pass

    yara_analyzer = yara_analyzer_cls(DummyR2(), config_obj)
    rules_path = yara or getattr(config_obj, "yara_rules_path", "r2inspect/rules/yara")
    rules_path = str(rules_path)

    available_rules = yara_analyzer.list_available_rules(rules_path)
    if available_rules:
        params = set()
        try:
            params = set(inspect.signature(display_yara_rules_table).parameters)
        except (TypeError, ValueError):
            params = set()
        if "get_console" in params:
            display_yara_rules_table(available_rules, rules_path, get_console=get_console)
        else:
            display_yara_rules_table(available_rules, rules_path)
        return

    get_console().print(f"[yellow]No YARA rules found in: {rules_path}[/yellow]")
    get_console().print(
        "[blue]You can place any .yar, .yara, .rule, or .rules files in this directory[/blue]"
    )


def display_error_statistics(error_stats: dict[str, Any], *, get_console: Any) -> None:
    get_console().print("\n[bold yellow]Error Statistics[/bold yellow]")
    table = Table(title="Analysis Error Summary", show_header=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="red")
    table.add_row("Total Errors", str(error_stats.get("total_errors", 0)))
    table.add_row("Recent Errors", str(error_stats.get("recent_errors", 0)))
    table.add_row(
        "Recovery Strategies Available", str(error_stats.get("recovery_strategies_available", 0))
    )
    get_console().print(table)

    errors_by_category = error_stats.get("errors_by_category", {})
    if isinstance(errors_by_category, dict) and errors_by_category:
        category_table = Table(title="Errors by Category", show_header=True)
        category_table.add_column("Category", style="cyan")
        category_table.add_column("Count", style="red")
        for category, count in errors_by_category.items():
            if hasattr(category, "value"):
                label = category.value if isinstance(category.value, str) and category.value else "unknown"
            else:
                label = str(category) if category is not None else "unknown"
            category_table.add_row(label.replace("_", " ").title(), str(count))
        get_console().print(category_table)

    errors_by_severity = error_stats.get("errors_by_severity", {})
    if isinstance(errors_by_severity, dict) and errors_by_severity:
        severity_table = Table(title="Errors by Severity", show_header=True)
        severity_table.add_column("Severity", style="cyan")
        severity_table.add_column("Count", style="red")
        for severity, count in errors_by_severity.items():
            severity_label = str(severity) if severity is not None else "unknown"
            color = (
                "red"
                if severity_label == "critical"
                else "yellow"
                if severity_label == "high"
                else "dim"
            )
            severity_table.add_row(f"[{color}]{severity_label.title()}[/{color}]", str(count))
        get_console().print(severity_table)

    get_console().print()


def display_performance_statistics(
    retry_stats: dict[str, Any],
    circuit_stats: dict[str, Any],
    *,
    get_console: Any,
    display_retry_statistics: Any,
    display_circuit_breaker_statistics: Any,
) -> None:
    get_console().print("\n[bold cyan]Performance Statistics[/bold cyan]")
    display_retry_statistics(retry_stats)
    display_circuit_breaker_statistics(circuit_stats)
    get_console().print()
