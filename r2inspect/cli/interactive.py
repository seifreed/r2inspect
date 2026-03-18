#!/usr/bin/env python3
"""Interactive CLI facade for exploratory binary analysis."""

from typing import Any

from rich.console import Console

from ..cli.output_formatters import OutputFormatter

console = Console()
HELP_LINES = (
    "Available commands:",
    "  analyze - Run full analysis",
    "  strings - Show strings",
    "  info    - Show file info",
    "  pe      - Show PE info",
    "  imports - Show imports",
    "  exports - Show exports",
    "  sections - Show sections",
    "  quit    - Exit",
)
HELP_SUMMARY = "Available commands: analyze, strings, info, pe, imports, exports, sections, quit"


def _active_console() -> Console:
    """Return the current console, recreating it if its file handle was closed."""
    global console
    file_obj = getattr(console, "file", None)
    if getattr(file_obj, "closed", False) is True:
        console = Console()
    return console


def show_strings_only(inspector: Any) -> None:
    """Render the extracted strings and nothing else."""
    active_console = _active_console()
    active_console.print("[bold green]Extracting strings...[/bold green]")
    for string in inspector.get_strings():
        active_console.print(string)


def _print_help() -> None:
    """Render the condensed help text for the interactive shell."""
    _active_console().print(HELP_SUMMARY)


def _show_info_table(title: str, data: dict[str, Any], formatter: OutputFormatter) -> None:
    """Render a small rich table for a metadata payload."""
    _active_console().print(formatter.format_table(data, title))


def _show_banner() -> None:
    """Render the interactive shell banner and the expanded command list."""
    active_console = _active_console()
    active_console.print("[bold blue]Interactive Mode - r2inspect[/bold blue]")
    for line in HELP_LINES:
        active_console.print(line)


def _build_handlers(
    inspector: Any, options: dict[str, Any], formatter: OutputFormatter
) -> dict[str, Any]:
    """Build command handlers for the interactive analysis loop."""
    from ..application.use_cases import AnalyzeBinaryUseCase
    from .display import display_results

    def _cmd_analyze() -> None:
        result = AnalyzeBinaryUseCase().run(
            inspector,
            options,
            reset_stats=False,
            include_statistics=False,
            validate_schemas=False,
        )
        display_results(result.to_dict())

    def _cmd_strings() -> None:
        show_strings_only(inspector)

    def _cmd_info() -> None:
        _show_info_table("File Information", inspector.get_file_info(), formatter)

    def _cmd_pe() -> None:
        _show_info_table("PE Information", inspector.get_pe_info(), formatter)

    def _print_items(items: list[Any]) -> None:
        active_console = _active_console()
        for item in items:
            active_console.print(item)

    def _cmd_imports() -> None:
        _print_items(inspector.get_imports())

    def _cmd_exports() -> None:
        _print_items(inspector.get_exports())

    def _cmd_sections() -> None:
        _active_console().print(formatter.format_sections(inspector.get_sections()))

    return {
        "analyze": _cmd_analyze,
        "strings": _cmd_strings,
        "info": _cmd_info,
        "pe": _cmd_pe,
        "imports": _cmd_imports,
        "exports": _cmd_exports,
        "sections": _cmd_sections,
        "help": _print_help,
    }


def run_interactive_mode(inspector: Any, options: dict[str, Any]) -> None:
    """Run the interactive shell used for exploratory analysis sessions."""
    formatter = OutputFormatter({})
    handlers = _build_handlers(inspector, options, formatter)
    _show_banner()

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
                active_console = _active_console()
                active_console.print(f"[red]Unknown command: {cmd}[/red]")
                active_console.print("Type 'help' for available commands")

        except KeyboardInterrupt:
            break
        except EOFError:
            break

    _active_console().print("[yellow]Exiting interactive mode...[/yellow]")


__all__ = [
    "HELP_LINES",
    "HELP_SUMMARY",
    "_print_help",
    "_show_info_table",
    "console",
    "run_interactive_mode",
    "show_strings_only",
]
