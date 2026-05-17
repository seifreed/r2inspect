#!/usr/bin/env python3
"""Interactive CLI facade for exploratory binary analysis."""

from collections.abc import Callable
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


def _resolve_console(injected: Any | None) -> Any:
    """Use an injected console when supplied, else the module default."""
    return injected if injected is not None else _active_console()


def show_strings_only(inspector: Any, console: Any | None = None) -> None:
    """Render the extracted strings and nothing else."""
    active_console = _resolve_console(console)
    active_console.print("[bold green]Extracting strings...[/bold green]")
    for string in inspector.get_strings():
        active_console.print(string)


def _print_help(console: Any | None = None) -> None:
    """Render the condensed help text for the interactive shell."""
    _resolve_console(console).print(HELP_SUMMARY)


def _show_info_table(
    title: str, data: dict[str, Any], formatter: OutputFormatter, console: Any | None = None
) -> None:
    """Render a small rich table for a metadata payload."""
    _resolve_console(console).print(formatter.format_table(data, title))


def _show_banner(console: Any | None = None) -> None:
    """Render the interactive shell banner and the expanded command list."""
    active_console = _resolve_console(console)
    active_console.print("[bold blue]Interactive Mode - r2inspect[/bold blue]")
    for line in HELP_LINES:
        active_console.print(line)


def _build_handlers(
    inspector: Any,
    options: dict[str, Any],
    formatter: OutputFormatter,
    *,
    console: Any | None = None,
    analyze_use_case: Callable[[], Any] | None = None,
    display_fn: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Build command handlers for the interactive analysis loop."""
    active_console = _resolve_console(console)
    if analyze_use_case is None:
        from ..application.use_cases import AnalyzeBinaryUseCase

        analyze_use_case = AnalyzeBinaryUseCase
    if display_fn is None:
        from .display import display_results

        display_fn = display_results

    def _cmd_analyze() -> None:
        result = analyze_use_case().run(
            inspector,
            options,
            reset_stats=False,
            include_statistics=False,
            validate_schemas=False,
        )
        display_fn(result.to_dict())

    def _cmd_strings() -> None:
        show_strings_only(inspector, active_console)

    def _cmd_info() -> None:
        _show_info_table("File Information", inspector.get_file_info(), formatter, active_console)

    def _cmd_pe() -> None:
        _show_info_table("PE Information", inspector.get_pe_info(), formatter, active_console)

    def _print_items(items: list[Any]) -> None:
        for item in items:
            active_console.print(item)

    def _cmd_imports() -> None:
        _print_items(inspector.get_imports())

    def _cmd_exports() -> None:
        _print_items(inspector.get_exports())

    def _cmd_sections() -> None:
        active_console.print(formatter.format_sections(inspector.get_sections()))

    return {
        "analyze": _cmd_analyze,
        "strings": _cmd_strings,
        "info": _cmd_info,
        "pe": _cmd_pe,
        "imports": _cmd_imports,
        "exports": _cmd_exports,
        "sections": _cmd_sections,
        "help": lambda: _print_help(active_console),
    }


def run_interactive_mode(
    inspector: Any,
    options: dict[str, Any],
    *,
    console: Any | None = None,
    formatter: OutputFormatter | None = None,
    input_fn: Callable[[str], str] | None = None,
    analyze_use_case: Callable[[], Any] | None = None,
    display_fn: Callable[[dict[str, Any]], None] | None = None,
) -> None:
    """Run the interactive shell used for exploratory analysis sessions."""
    active_console = _resolve_console(console)
    formatter = formatter if formatter is not None else OutputFormatter({})
    read_command = input_fn if input_fn is not None else input
    handlers = _build_handlers(
        inspector,
        options,
        formatter,
        console=active_console,
        analyze_use_case=analyze_use_case,
        display_fn=display_fn,
    )
    _show_banner(active_console)

    while True:
        try:
            cmd = read_command("\nr2inspect> ").strip().lower()

            if cmd == "quit" or cmd == "exit":
                break
            elif cmd == "":
                continue
            elif cmd in handlers:
                handlers[cmd]()
            else:
                active_console.print(f"[red]Unknown command: {cmd}[/red]")
                active_console.print("Type 'help' for available commands")

        except KeyboardInterrupt:
            break
        except EOFError:
            break

    active_console.print("[yellow]Exiting interactive mode...[/yellow]")


__all__ = [
    "HELP_LINES",
    "HELP_SUMMARY",
    "_print_help",
    "_show_info_table",
    "console",
    "run_interactive_mode",
    "show_strings_only",
]
