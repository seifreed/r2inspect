#!/usr/bin/env python3
"""
r2inspect CLI Display Base Module

Shared helpers, constants, and top-level display entry points.
"""

import sys
from typing import IO, Any, cast

from rich.console import Console
from rich.table import Table

from ..config import Config
from .presenter import normalize_display_results

pyfiglet: Any | None
try:
    import pyfiglet as _pyfiglet

    pyfiglet = _pyfiglet
except Exception:  # pragma: no cover - optional dependency
    pyfiglet = None


class _StdoutProxy:
    def write(self, data: str) -> int:
        return sys.stdout.write(data)

    def flush(self) -> None:
        sys.stdout.flush()

    def isatty(self) -> bool:
        return sys.stdout.isatty()

    @property
    def encoding(self) -> str:
        return getattr(sys.stdout, "encoding", "utf-8")

    @property
    def errors(self) -> str:
        return getattr(sys.stdout, "errors", "strict")


console = Console(file=cast(IO[str], _StdoutProxy()))
DEFAULT_CONSOLE = console


def _get_console() -> Console:
    from . import display as display_module

    return display_module.console


# Constants
UNKNOWN_ERROR = "Unknown error"
NOT_AVAILABLE = "Not Available"
HTML_AMP = "&amp;"
STATUS_AVAILABLE = "[green]✓ Available[/green]"
STATUS_NOT_AVAILABLE = "[red]✗ Not Available[/red]"
STATUS_NOT_AVAILABLE_SIMPLE = "[red]Not Available[/red]"
TOTAL_FUNCTIONS_LABEL = "Total Functions"
ANALYZED_FUNCTIONS_LABEL = "Analyzed Functions"
SIMILAR_GROUPS_LABEL = "Similar Function Groups"


def format_hash_display(hash_value: Any, max_length: int = 32) -> str:
    """Standardize hash display format"""
    if not hash_value or hash_value == "N/A":
        return "N/A"
    hash_str = str(hash_value)
    if len(hash_str) > max_length:
        return f"{hash_str[:max_length]}..."
    return hash_str


def create_info_table(title: str, prop_width: int = 15, value_min_width: int = 50) -> Table:
    """Create a standardized info table with proper sizing"""
    table = Table(title=title, show_header=True, expand=True)
    table.add_column("Property", style="cyan", width=prop_width, no_wrap=True)
    table.add_column("Value", style="green", min_width=value_min_width, overflow="fold")
    return table


def print_banner() -> None:
    """Print r2inspect banner"""
    try:
        if pyfiglet is not None:
            banner = pyfiglet.figlet_format("r2inspect", font="slant")
            _get_console().print(f"[bold blue]{banner}[/bold blue]")
        else:
            _get_console().print("[bold blue]r2inspect[/bold blue]")
        _get_console().print("[bold]Advanced Malware Analysis Tool using Radare2[/bold]")
        _get_console().print("[dim]Professional malware analysis powered by radare2[/dim]\n")
    except Exception:  # pragma: no cover
        # Fallback simple banner if pyfiglet/rich fails
        print("r2inspect - Advanced Malware Analysis Tool using Radare2")
        print("Professional malware analysis powered by radare2")
        print()


def display_validation_errors(validation_errors: list[str]) -> None:
    """Display validation errors and exit"""
    for error in validation_errors:
        _get_console().print(f"[red]Error: {error}[/red]")


def handle_list_yara_option(config: Any, yara: str | None) -> None:
    """Handle the --list-yara option"""
    config_obj = Config(config)
    from ..modules.yara_analyzer import YaraAnalyzer

    # Initialize a dummy r2 object
    class DummyR2:
        pass

    yara_analyzer = YaraAnalyzer(DummyR2(), config_obj)
    rules_path = yara or getattr(config_obj, "yara_rules_path", "r2inspect/rules/yara")
    rules_path = str(rules_path)

    available_rules = yara_analyzer.list_available_rules(rules_path)

    if available_rules:
        display_yara_rules_table(available_rules, rules_path)
    else:
        _get_console().print(f"[yellow]No YARA rules found in: {rules_path}[/yellow]")
        _get_console().print(
            "[blue]You can place any .yar, .yara, .rule, or .rules files in this directory[/blue]"
        )


def display_yara_rules_table(available_rules: list[dict[str, Any]], rules_path: str) -> None:
    """Display YARA rules in a table format"""
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

    _get_console().print(table)
    _get_console().print(f"\n[green]Total: {len(available_rules)} YARA rule file(s) found[/green]")
    _get_console().print(
        "[blue]All these files will be automatically loaded when running analysis[/blue]"
    )


def display_error_statistics(error_stats: dict[str, Any]) -> None:
    """Display error statistics in verbose mode"""
    _get_console().print("\n[bold yellow]Error Statistics[/bold yellow]")

    # Create error statistics table
    table = Table(title="Analysis Error Summary", show_header=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="red")

    table.add_row("Total Errors", str(error_stats["total_errors"]))
    table.add_row("Recent Errors", str(error_stats["recent_errors"]))
    table.add_row(
        "Recovery Strategies Available",
        str(error_stats["recovery_strategies_available"]),
    )

    _get_console().print(table)

    # Show errors by category if available
    if error_stats["errors_by_category"]:
        category_table = Table(title="Errors by Category", show_header=True)
        category_table.add_column("Category", style="cyan")
        category_table.add_column("Count", style="red")

        for category, count in error_stats["errors_by_category"].items():
            label = str(category.value) if hasattr(category, "value") else str(category)
            category_table.add_row(label.replace("_", " ").title(), str(count))

        _get_console().print(category_table)

    # Show errors by severity if available
    if error_stats["errors_by_severity"]:
        severity_table = Table(title="Errors by Severity", show_header=True)
        severity_table.add_column("Severity", style="cyan")
        severity_table.add_column("Count", style="red")

        for severity, count in error_stats["errors_by_severity"].items():
            if severity == "critical":
                color = "red"
            elif severity == "high":
                color = "yellow"
            else:
                color = "dim"
            severity_table.add_row(f"[{color}]{severity.title()}[/{color}]", str(count))

        _get_console().print(severity_table)

    _get_console().print()


def display_performance_statistics(
    retry_stats: dict[str, Any], circuit_stats: dict[str, Any]
) -> None:
    """Display retry and circuit breaker statistics in verbose mode"""
    _get_console().print("\n[bold cyan]Performance Statistics[/bold cyan]")

    from .display_statistics import _display_circuit_breaker_statistics, _display_retry_statistics

    _display_retry_statistics(retry_stats)
    _display_circuit_breaker_statistics(circuit_stats)
    _get_console().print()


def display_results(results: dict[str, Any]) -> None:
    """Display analysis results in a formatted table"""
    results = normalize_display_results(results)
    from . import display as display_module
    from .display_sections import (
        _display_binbloom,
        _display_bindiff,
        _display_binlex,
        _display_ccbhash,
        _display_file_info,
        _display_impfuzzy,
        _display_indicators,
        _display_machoc_functions,
        _display_pe_info,
        _display_rich_header,
        _display_security,
        _display_simhash,
        _display_ssdeep,
        _display_telfhash,
        _display_tlsh,
    )

    display_funcs = [
        _display_file_info,
        _display_pe_info,
        _display_security,
        _display_ssdeep,
        _display_tlsh,
        _display_telfhash,
        _display_rich_header,
        _display_impfuzzy,
        _display_ccbhash,
        _display_binlex,
        _display_binbloom,
        _display_simhash,
        _display_bindiff,
        _display_machoc_functions,
        _display_indicators,
    ]

    for func in display_funcs:
        func(results)
