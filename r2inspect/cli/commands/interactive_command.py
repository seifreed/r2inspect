#!/usr/bin/env python3
"""Interactive CLI command."""

from typing import Any

from ...application.use_cases import AnalyzeBinaryUseCase
from ...factory import create_inspector
from . import interactive_runtime as _interactive_runtime
from .base import Command


class InteractiveCommand(Command):
    """Interactive analysis command."""

    def execute(self, args: dict[str, Any]) -> int:
        """Execute interactive mode."""
        filename = args["filename"]
        config = self._get_config(args.get("config"))
        verbose = args.get("verbose", False)

        try:
            self.context.console.print(f"[blue]Initializing analysis for: {filename}[/blue]")
            analysis_options = self._setup_analysis_options(
                yara=args.get("yara"),
                xor=args.get("xor"),
            )
            with create_inspector(
                filename=filename,
                config=config,
                verbose=verbose,
            ) as inspector:
                self._run_interactive_mode(inspector, analysis_options)

            return 0

        except KeyboardInterrupt:  # pragma: no cover
            self.context.console.print("\n[yellow]Interactive mode interrupted by user[/yellow]")
            return 1

        except Exception as e:
            self._handle_error(e, verbose, "Interactive mode")
            return 1

    def _run_interactive_mode(
        self,
        inspector: Any,
        options: dict[str, Any],
    ) -> None:
        """Run the interactive REPL."""
        self._display_welcome()

        while True:
            try:
                cmd = input("\nr2inspect> ").strip().lower()

                if self._should_exit(cmd):
                    break

                if cmd == "":
                    continue

                self._execute_interactive_command(cmd, inspector, options)

            except KeyboardInterrupt:  # pragma: no cover
                break
            except EOFError:
                break
            except Exception as e:
                self.context.console.print(f"[red]Command error: {e}[/red]")

        self.context.console.print("[yellow]Exiting interactive mode...[/yellow]")

    def _display_welcome(self) -> None:
        _interactive_runtime.display_welcome(self.context.console)

    def _should_exit(self, cmd: str) -> bool:
        """Return whether the command exits the REPL."""
        return cmd in ("quit", "exit", "q")

    def _execute_interactive_command(
        self,
        cmd: str,
        inspector: Any,
        options: dict[str, Any],
    ) -> None:
        _interactive_runtime.execute_command(self, cmd, inspector, options)

    def _cmd_analyze(
        self,
        inspector: Any,
        options: dict[str, Any],
        display_results: Any,
    ) -> None:
        _interactive_runtime.run_analyze(self, inspector, options, display_results)

    def _analyze_binary_use_case(self) -> Any:
        return AnalyzeBinaryUseCase()

    def _cmd_strings(self, inspector: Any) -> None:
        _interactive_runtime.show_strings(self.context.console, inspector)

    def _cmd_info(self, inspector: Any) -> None:
        _interactive_runtime.show_file_info(self.context.console, inspector)

    def _cmd_pe(self, inspector: Any) -> None:
        _interactive_runtime.show_pe_info(self.context.console, inspector)

    def _cmd_imports(self, inspector: Any) -> None:
        _interactive_runtime.show_lines(self.context.console, inspector.get_imports())

    def _cmd_exports(self, inspector: Any) -> None:
        _interactive_runtime.show_lines(self.context.console, inspector.get_exports())

    def _cmd_sections(self, inspector: Any) -> None:
        _interactive_runtime.show_sections(self.context.console, inspector)
