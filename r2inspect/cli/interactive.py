#!/usr/bin/env python3
"""
r2inspect CLI Interactive Mode Module

Provides interactive command-line interface for malware analysis.
Extracted from cli_utils.py for better modularity.

Copyright (C) 2025 Marc Rivero López

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

from rich.console import Console

from ..utils.output import OutputFormatter

console = Console()


def show_strings_only(inspector):
    """
    Show only strings analysis.

    Args:
        inspector: R2Inspector instance
    """
    console.print("[bold green]Extracting strings...[/bold green]")
    strings = inspector.get_strings()

    for string in strings:
        console.print(string)


def _print_help() -> None:
    console.print(
        "Available commands: analyze, strings, info, pe, imports, exports, sections, quit"
    )


def _show_info_table(title: str, data: dict, formatter: OutputFormatter) -> None:
    console.print(formatter.format_table(data, title))


def run_interactive_mode(inspector, options):
    """
    Run interactive analysis mode.

    Provides a command-line interface for exploring binary analysis.

    Args:
        inspector: R2Inspector instance
        options: Analysis options dictionary
    """
    # Import here to avoid circular dependency
    from .display import display_results

    console.print("[bold blue]Interactive Mode - r2inspect[/bold blue]")
    console.print("Available commands:")
    console.print("  analyze - Run full analysis")
    console.print("  strings - Show strings")
    console.print("  info    - Show file info")
    console.print("  pe      - Show PE info")
    console.print("  imports - Show imports")
    console.print("  exports - Show exports")
    console.print("  sections - Show sections")
    console.print("  quit    - Exit")

    formatter = OutputFormatter({})

    def _cmd_analyze() -> None:
        results = inspector.analyze(**options)
        display_results(results)

    def _cmd_strings() -> None:
        show_strings_only(inspector)

    def _cmd_info() -> None:
        info = inspector.get_file_info()
        _show_info_table("File Information", info, formatter)

    def _cmd_pe() -> None:
        pe_info = inspector.get_pe_info()
        _show_info_table("PE Information", pe_info, formatter)

    def _cmd_imports() -> None:
        for imp in inspector.get_imports():
            console.print(imp)

    def _cmd_exports() -> None:
        for exp in inspector.get_exports():
            console.print(exp)

    def _cmd_sections() -> None:
        sections = inspector.get_sections()
        console.print(formatter.format_sections(sections))

    handlers = {
        "analyze": _cmd_analyze,
        "strings": _cmd_strings,
        "info": _cmd_info,
        "pe": _cmd_pe,
        "imports": _cmd_imports,
        "exports": _cmd_exports,
        "sections": _cmd_sections,
        "help": _print_help,
    }

    while True:
        try:
            cmd = input("\nr2inspect> ").strip().lower()

            if cmd == "quit" or cmd == "exit":
                break
            elif cmd == "":
                continue
            elif cmd in handlers:
                handlers[cmd]()
            else:
                console.print(f"[red]Unknown command: {cmd}[/red]")
                console.print("Type 'help' for available commands")

        except KeyboardInterrupt:
            break
        except EOFError:
            break

    console.print("[yellow]Exiting interactive mode...[/yellow]")
