#!/usr/bin/env python3
"""Base abstractions for CLI commands."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from rich.console import Console

from ...config import Config
from .context_runtime import create_command_context as _create_command_context
from .context_runtime import resolve_config as _resolve_config
from ..command_runtime import (
    apply_thread_settings as _apply_thread_settings,
    build_analysis_options as _build_analysis_options,
    configure_logging_levels as _configure_logging_levels,
    configure_quiet_logging as _configure_quiet_logging,
)

configure_logging_levels = _configure_logging_levels
configure_quiet_logging = _configure_quiet_logging
apply_thread_settings = _apply_thread_settings


@dataclass
class CommandContext:
    """Shared state and dependencies for CLI commands."""

    console: Console
    logger: Any
    config: Config | None = None
    verbose: bool = False
    quiet: bool = False

    @classmethod
    def create(
        cls,
        config: Config | None = None,
        verbose: bool = False,
        quiet: bool = False,
        thread_safe: bool = False,
    ) -> "CommandContext":
        """Create a fully initialized command context."""
        console, logger, resolved_config = _create_command_context(
            config=config,
            verbose=verbose,
            quiet=quiet,
            thread_safe=thread_safe,
            configure_logging_levels=configure_logging_levels,
        )

        return cls(
            console=console,
            logger=logger,
            config=resolved_config,
            verbose=verbose,
            quiet=quiet,
        )


class Command(ABC):
    """Abstract base class for CLI commands."""

    def __init__(self, context: CommandContext | None = None):
        self._context = context

    @abstractmethod
    def execute(self, args: dict[str, Any]) -> int:
        """Execute the command and return a process exit code."""
        pass

    @property
    def context(self) -> CommandContext:
        """Return the command context, creating a default one on demand."""
        if self._context is None:
            self._context = CommandContext.create()
        return self._context

    @context.setter
    def context(self, value: CommandContext) -> None:
        self._context = value

    def _get_config(self, config_path: str | None = None) -> Config:
        """Load configuration from a custom path or from the current context."""
        return _resolve_config(self.context.config, config_path)

    def _setup_analysis_options(
        self,
        yara: str | None = None,
        xor: str | None = None,
    ) -> dict[str, Any]:
        """Build the standardized analysis-options dictionary."""
        return _build_analysis_options(yara, xor)

    def _handle_error(
        self, error: Exception, verbose: bool, context_label: str = "Analysis"
    ) -> None:
        """Render command errors using verbose or concise CLI output."""
        self.context.logger.error("Error during %s: %s", context_label.lower(), error)
        if verbose:
            import traceback

            self.context.console.print(f"[red]Error: {error}[/red]")
            self.context.console.print(f"[dim]{traceback.format_exc()}[/dim]")
            return
        self.context.console.print(f"[red]{context_label} failed: {error}[/red]")
        self.context.console.print("[dim]Use --verbose for detailed error information[/dim]")


__all__ = [
    "Command",
    "CommandContext",
    "apply_thread_settings",
    "configure_logging_levels",
    "configure_quiet_logging",
]
