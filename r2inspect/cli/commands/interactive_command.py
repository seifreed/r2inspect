#!/usr/bin/env python3
"""
r2inspect CLI Commands - Interactive Command

Interactive mode command implementation.

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

from typing import Any

from ...core import R2Inspector
from ...utils.output import OutputFormatter
from .base import Command


class InteractiveCommand(Command):
    """
    Command for interactive analysis mode.

    Provides a REPL (Read-Eval-Print Loop) interface for step-by-step
    binary analysis, allowing users to execute specific analysis commands
    on demand without re-running the entire analysis pipeline.

    Supported interactive commands:
    - analyze: Run full analysis
    - strings: Show strings
    - info: Show file information
    - pe: Show PE information
    - imports: Show imports table
    - exports: Show exports table
    - sections: Show sections table
    - help: Display available commands
    - quit/exit: Exit interactive mode

    Responsibilities:
    - Initialize R2Inspector session
    - Provide command-line interface for incremental analysis
    - Execute specific analysis modules on demand
    - Display formatted results for each command
    """

    def execute(self, args: dict[str, Any]) -> int:
        """
        Execute interactive analysis mode.

        Args:
            args: Dictionary containing:
                - filename: Path to file to analyze
                - config: Optional config file path
                - yara: Optional YARA rules directory
                - xor: Optional XOR search string
                - verbose: Verbose output flag

        Returns:
            0 on success, 1 on failure
        """
        filename = args["filename"]
        config = self._get_config(args.get("config"))
        verbose = args.get("verbose", False)

        try:
            self.context.console.print(f"[blue]Initializing analysis for: {filename}[/blue]")

            # Configure analysis options
            analysis_options = self._setup_analysis_options(
                yara=args.get("yara"),
                xor=args.get("xor"),
            )

            # Initialize R2Inspector with context manager for proper cleanup
            with R2Inspector(
                filename=filename,
                config=config,
                verbose=verbose,
            ) as inspector:
                # Run interactive mode
                self._run_interactive_mode(inspector, analysis_options)

            return 0

        except KeyboardInterrupt:
            self.context.console.print("\n[yellow]Interactive mode interrupted by user[/yellow]")
            return 0  # Normal exit for Ctrl+C in interactive mode

        except Exception as e:
            self._handle_error(e, verbose)
            return 1

    def _run_interactive_mode(
        self,
        inspector: R2Inspector,
        options: dict[str, Any],
    ) -> None:
        """
        Run interactive analysis mode with REPL interface.

        Provides a command-line interface for executing analysis commands
        interactively. Handles command parsing, execution, and output.

        Args:
            inspector: Initialized R2Inspector instance
            options: Analysis options dictionary
        """
        self._display_welcome()

        while True:
            try:
                cmd = input("\nr2inspect> ").strip().lower()

                if self._should_exit(cmd):
                    break

                if cmd == "":
                    continue

                self._execute_interactive_command(cmd, inspector, options)

            except KeyboardInterrupt:
                break
            except EOFError:
                break
            except Exception as e:
                self.context.console.print(f"[red]Command error: {e}[/red]")

        self.context.console.print("[yellow]Exiting interactive mode...[/yellow]")

    def _display_welcome(self) -> None:
        """Display welcome message and available commands."""
        self.context.console.print("[bold blue]Interactive Mode - r2inspect[/bold blue]")
        self.context.console.print("Available commands:")
        self.context.console.print("  analyze  - Run full analysis")
        self.context.console.print("  strings  - Show strings")
        self.context.console.print("  info     - Show file info")
        self.context.console.print("  pe       - Show PE info")
        self.context.console.print("  imports  - Show imports")
        self.context.console.print("  exports  - Show exports")
        self.context.console.print("  sections - Show sections")
        self.context.console.print("  help     - Show this help message")
        self.context.console.print("  quit     - Exit")

    def _should_exit(self, cmd: str) -> bool:
        """
        Check if command is an exit command.

        Args:
            cmd: Command string

        Returns:
            True if exit command, False otherwise
        """
        return cmd in ("quit", "exit", "q")

    def _execute_interactive_command(
        self,
        cmd: str,
        inspector: R2Inspector,
        options: dict[str, Any],
    ) -> None:
        """
        Execute a single interactive command.

        Dispatches command to appropriate handler method based on
        command name.

        Args:
            cmd: Command string
            inspector: R2Inspector instance
            options: Analysis options dictionary
        """
        # Import display functions from cli module
        from .. import display_results

        command_handlers = {
            "analyze": lambda: self._cmd_analyze(inspector, options, display_results),
            "strings": lambda: self._cmd_strings(inspector),
            "info": lambda: self._cmd_info(inspector),
            "pe": lambda: self._cmd_pe(inspector),
            "imports": lambda: self._cmd_imports(inspector),
            "exports": lambda: self._cmd_exports(inspector),
            "sections": lambda: self._cmd_sections(inspector),
            "help": lambda: self._display_welcome(),
        }

        handler = command_handlers.get(cmd)

        if handler:
            handler()
        else:
            self.context.console.print(f"[red]Unknown command: {cmd}[/red]")
            self.context.console.print("Type 'help' for available commands")

    def _cmd_analyze(
        self,
        inspector: R2Inspector,
        options: dict[str, Any],
        display_results: Any,
    ) -> None:
        """
        Execute full analysis command.

        Args:
            inspector: R2Inspector instance
            options: Analysis options dictionary
            display_results: Display function for results
        """
        self.context.console.print("[bold green]Running full analysis...[/bold green]")
        results = inspector.analyze(**options)
        display_results(results)

    def _cmd_strings(self, inspector: R2Inspector) -> None:
        """
        Execute strings extraction command.

        Args:
            inspector: R2Inspector instance
        """
        self.context.console.print("[bold green]Extracting strings...[/bold green]")
        strings = inspector.get_strings()

        for string in strings:
            self.context.console.print(string)

    def _cmd_info(self, inspector: R2Inspector) -> None:
        """
        Execute file info command.

        Args:
            inspector: R2Inspector instance
        """
        info = inspector.get_file_info()
        formatter = OutputFormatter({"file_info": info})
        self.context.console.print(formatter.format_table(info, "File Information"))

    def _cmd_pe(self, inspector: R2Inspector) -> None:
        """
        Execute PE info command.

        Args:
            inspector: R2Inspector instance
        """
        pe_info = inspector.get_pe_info()
        formatter = OutputFormatter({"pe_info": pe_info})
        self.context.console.print(formatter.format_table(pe_info, "PE Information"))

    def _cmd_imports(self, inspector: R2Inspector) -> None:
        """
        Execute imports display command.

        Args:
            inspector: R2Inspector instance
        """
        imports = inspector.get_imports()
        for imp in imports:
            self.context.console.print(imp)

    def _cmd_exports(self, inspector: R2Inspector) -> None:
        """
        Execute exports display command.

        Args:
            inspector: R2Inspector instance
        """
        exports = inspector.get_exports()
        for exp in exports:
            self.context.console.print(exp)

    def _cmd_sections(self, inspector: R2Inspector) -> None:
        """
        Execute sections display command.

        Args:
            inspector: R2Inspector instance
        """
        sections = inspector.get_sections()
        formatter = OutputFormatter({"sections": sections})
        self.context.console.print(formatter.format_sections(sections))

    def _handle_error(self, error: Exception, verbose: bool) -> None:
        """
        Handle interactive mode errors with appropriate logging and output.

        Args:
            error: Exception that occurred
            verbose: Verbose output flag for detailed error info
        """
        self.context.logger.error(f"Error in interactive mode: {error}")

        if verbose:
            self.context.console.print(f"[red]Error: {error}[/red]")
            import traceback

            self.context.console.print(f"[dim]{traceback.format_exc()}[/dim]")
        else:
            self.context.console.print(f"[red]Interactive mode failed: {error}[/red]")
            self.context.console.print("[dim]Use --verbose for detailed error information[/dim]")
