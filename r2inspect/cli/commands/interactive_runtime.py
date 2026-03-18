#!/usr/bin/env python3
"""Runtime helpers for the interactive CLI command."""

from __future__ import annotations

from typing import Any
from ...cli.output_formatters import OutputFormatter


def display_welcome(console: Any) -> None:
    console.print("[bold blue]Interactive Mode - r2inspect[/bold blue]")
    console.print("Available commands:")
    console.print("  analyze  - Run full analysis")
    console.print("  strings  - Show strings")
    console.print("  info     - Show file info")
    console.print("  pe       - Show PE info")
    console.print("  imports  - Show imports")
    console.print("  exports  - Show exports")
    console.print("  sections - Show sections")
    console.print("  help     - Show this help message")
    console.print("  quit     - Exit")


def execute_command(command: Any, cmd: str, inspector: Any, options: dict[str, Any]) -> None:
    from .. import display_results

    command_handlers = {
        "analyze": lambda: run_analyze(command, inspector, options, display_results),
        "strings": lambda: show_strings(command.context.console, inspector),
        "info": lambda: show_file_info(command.context.console, inspector),
        "pe": lambda: show_pe_info(command.context.console, inspector),
        "imports": lambda: show_lines(command.context.console, inspector.get_imports()),
        "exports": lambda: show_lines(command.context.console, inspector.get_exports()),
        "sections": lambda: show_sections(command.context.console, inspector),
        "help": lambda: display_welcome(command.context.console),
    }

    handler = command_handlers.get(cmd)
    if handler:
        handler()
        return

    command.context.console.print(f"[red]Unknown command: {cmd}[/red]")
    command.context.console.print("Type 'help' for available commands")


def run_analyze(
    command: Any, inspector: Any, options: dict[str, Any], display_results: Any
) -> None:
    command.context.console.print("[bold green]Running full analysis...[/bold green]")
    result = command._analyze_binary_use_case().run(
        inspector,
        options,
        reset_stats=False,
        include_statistics=False,
        validate_schemas=False,
    )
    display_results(result.to_dict())


def show_strings(console: Any, inspector: Any) -> None:
    strings = inspector.get_strings()
    console.print("[bold green]Extracting strings...[/bold green]")
    for value in strings:
        console.print(value)


def show_file_info(console: Any, inspector: Any) -> None:
    info = inspector.get_file_info()
    formatter = OutputFormatter({"file_info": info})
    console.print(formatter.format_table(info, "File Information"))


def show_pe_info(console: Any, inspector: Any) -> None:
    pe_info = inspector.get_pe_info()
    formatter = OutputFormatter({"pe_info": pe_info})
    console.print(formatter.format_table(pe_info, "PE Information"))


def show_lines(console: Any, values: list[Any]) -> None:
    for value in values:
        console.print(value)


def show_sections(console: Any, inspector: Any) -> None:
    sections = inspector.get_sections()
    formatter = OutputFormatter({"sections": sections})
    console.print(formatter.format_sections(sections))
