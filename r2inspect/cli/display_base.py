#!/usr/bin/env python3
"""Shared helpers, constants, and top-level display entry points."""

import sys
from typing import IO, Any, cast

from rich.console import Console
from rich.table import Table

from ..config import Config
from . import display_runtime as _display_runtime
from .presenter import normalize_display_results

pyfiglet: Any | None
try:
    import pyfiglet as _pyfiglet

    pyfiglet = _pyfiglet
except Exception:  # pragma: no cover - optional dependency
    pyfiglet = None


class _StdoutProxy:
    """Minimal text stream wrapper exposing stdout attributes Rich expects."""

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
    """Resolve the current display console from the public display facade."""
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
    """Normalize hash values for display tables."""
    if not hash_value or hash_value == "N/A":
        return "N/A"
    hash_str = str(hash_value)
    if len(hash_str) > max_length:
        return f"{hash_str[:max_length]}..."
    return hash_str


def create_info_table(title: str, prop_width: int = 15, value_min_width: int = 50) -> Table:
    """Create a standard two-column information table."""
    table = Table(title=title, show_header=True, expand=True)
    table.add_column("Property", style="cyan", width=prop_width, no_wrap=True)
    table.add_column("Value", style="green", min_width=value_min_width, overflow="fold")
    return table


def print_banner() -> None:
    """Print the CLI banner."""
    _display_runtime.print_banner(get_console=_get_console, pyfiglet=pyfiglet)


def display_validation_errors(validation_errors: list[str]) -> None:
    """Print CLI validation errors."""
    for error in validation_errors:
        _get_console().print(f"[red]Error: {error}[/red]")


def handle_list_yara_option(config: Any, yara: str | None) -> None:
    """Handle the ``--list-yara`` option."""
    _display_runtime.handle_list_yara_option(
        config,
        yara,
        config_cls=Config,
        display_yara_rules_table=display_yara_rules_table,
        get_console=_get_console,
    )


def display_yara_rules_table(available_rules: list[dict[str, Any]], rules_path: str) -> None:
    """Render the YARA rules table."""
    _display_runtime.display_yara_rules_table(
        available_rules,
        rules_path,
        get_console=_get_console,
    )


def display_error_statistics(error_stats: dict[str, Any]) -> None:
    """Render verbose error statistics."""
    _display_runtime.display_error_statistics(error_stats, get_console=_get_console)


def display_performance_statistics(
    retry_stats: dict[str, Any], circuit_stats: dict[str, Any]
) -> None:
    """Render retry and circuit-breaker statistics."""
    from .display_statistics import _display_circuit_breaker_statistics, _display_retry_statistics

    _display_runtime.display_performance_statistics(
        retry_stats,
        circuit_stats,
        get_console=_get_console,
        display_retry_statistics=_display_retry_statistics,
        display_circuit_breaker_statistics=_display_circuit_breaker_statistics,
    )


def display_results(results: dict[str, Any]) -> None:
    """Normalize and render analysis results."""
    results = normalize_display_results(results)
    from .display_dispatch import display_results_sections as _display_results_sections

    _display_results_sections(results)


__all__ = [
    "ANALYZED_FUNCTIONS_LABEL",
    "DEFAULT_CONSOLE",
    "HTML_AMP",
    "NOT_AVAILABLE",
    "SIMILAR_GROUPS_LABEL",
    "STATUS_AVAILABLE",
    "STATUS_NOT_AVAILABLE",
    "STATUS_NOT_AVAILABLE_SIMPLE",
    "TOTAL_FUNCTIONS_LABEL",
    "UNKNOWN_ERROR",
    "_StdoutProxy",
    "_get_console",
    "console",
    "create_info_table",
    "display_error_statistics",
    "display_performance_statistics",
    "display_results",
    "display_validation_errors",
    "display_yara_rules_table",
    "format_hash_display",
    "handle_list_yara_option",
    "print_banner",
]
