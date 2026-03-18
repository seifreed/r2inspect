#!/usr/bin/env python3
"""Shared runtime helpers for display facades."""

from __future__ import annotations

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
    table = Table(title=f"Available YARA Rules in: {rules_path}")
    table.add_column("Rule File", style="cyan")
    table.add_column("Size", style="yellow")
    table.add_column("Path", style="green")

    for rule in available_rules:
        size_kb = rule["size"] / 1024
        table.add_row(
            rule["name"],
            f"{size_kb:.1f} KB",
            rule.get("relative_path", rule["path"]),
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
) -> None:
    from ..modules.yara_analyzer import YaraAnalyzer

    config_obj = config_cls(config)

    class DummyR2:
        pass

    yara_analyzer = YaraAnalyzer(DummyR2(), config_obj)
    rules_path = yara or getattr(config_obj, "yara_rules_path", "r2inspect/rules/yara")
    rules_path = str(rules_path)

    available_rules = yara_analyzer.list_available_rules(rules_path)
    if available_rules:
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
    table.add_row("Total Errors", str(error_stats["total_errors"]))
    table.add_row("Recent Errors", str(error_stats["recent_errors"]))
    table.add_row(
        "Recovery Strategies Available", str(error_stats["recovery_strategies_available"])
    )
    get_console().print(table)

    if error_stats["errors_by_category"]:
        category_table = Table(title="Errors by Category", show_header=True)
        category_table.add_column("Category", style="cyan")
        category_table.add_column("Count", style="red")
        for category, count in error_stats["errors_by_category"].items():
            label = str(category.value) if hasattr(category, "value") else str(category)
            category_table.add_row(label.replace("_", " ").title(), str(count))
        get_console().print(category_table)

    if error_stats["errors_by_severity"]:
        severity_table = Table(title="Errors by Severity", show_header=True)
        severity_table.add_column("Severity", style="cyan")
        severity_table.add_column("Count", style="red")
        for severity, count in error_stats["errors_by_severity"].items():
            color = "red" if severity == "critical" else "yellow" if severity == "high" else "dim"
            severity_table.add_row(f"[{color}]{severity.title()}[/{color}]", str(count))
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
