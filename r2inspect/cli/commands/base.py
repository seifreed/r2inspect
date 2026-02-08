#!/usr/bin/env python3
"""
r2inspect CLI Commands - Base Abstractions

Command Pattern implementation for r2inspect CLI commands.

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

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from rich.console import Console

from ...config import Config
from ...utils.logger import get_logger, setup_logger


def configure_logging_levels(verbose: bool, quiet: bool) -> None:
    """Configure logging levels based on verbosity settings."""
    import logging
    import warnings

    if quiet:
        warnings.filterwarnings("ignore")
        logging.getLogger("r2pipe").setLevel(logging.CRITICAL)
        logging.getLogger("r2inspect").setLevel(logging.WARNING)
        logging.getLogger("r2inspect.modules").setLevel(logging.WARNING)
        logging.getLogger("r2inspect.pipeline").setLevel(logging.WARNING)
        return

    level = logging.INFO if verbose else logging.WARNING
    logging.getLogger("r2inspect").setLevel(level)
    logging.getLogger("r2inspect.modules").setLevel(level)
    logging.getLogger("r2inspect.pipeline").setLevel(level)


def configure_quiet_logging(quiet: bool) -> None:
    """Configure logging for quiet mode only."""
    import logging

    if not quiet:
        return

    logging.getLogger("r2pipe").setLevel(logging.CRITICAL)
    logging.getLogger("r2inspect").setLevel(logging.WARNING)
    logging.getLogger("r2inspect.modules").setLevel(logging.WARNING)
    logging.getLogger("r2inspect.pipeline").setLevel(logging.WARNING)


def apply_thread_settings(config: Config, threads: int | None) -> None:
    """Map threads setting to pipeline configuration if provided."""
    if threads is None:
        return

    try:
        t = int(threads)
        config.apply_overrides({"pipeline": {"max_workers": t, "parallel_execution": bool(t > 1)}})
    except Exception:
        # Keep configuration unchanged if conversion fails
        return


@dataclass
class CommandContext:
    """
    Shared context for all commands.

    Encapsulates common state and dependencies used across different CLI commands,
    following the Context Object pattern to reduce coupling and improve testability.

    Attributes:
        console: Rich console for formatted output
        logger: Logger instance for command execution logging
        config: Application configuration object
        verbose: Flag for verbose output mode
        quiet: Flag for suppressing non-critical output
    """

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
        """
        Factory method to create a CommandContext with proper initialization.

        Args:
            config: Optional configuration object
            verbose: Enable verbose output
            quiet: Suppress non-critical output
            thread_safe: Enable thread-safe logging for batch operations

        Returns:
            Configured CommandContext instance
        """
        console = Console()
        logger = setup_logger(thread_safe=thread_safe)

        configure_logging_levels(verbose, quiet)

        return cls(
            console=console,
            logger=logger,
            config=config or Config(),
            verbose=verbose,
            quiet=quiet,
        )


class Command(ABC):
    """
    Abstract base class for all CLI commands.

    Implements the Command Pattern, providing a uniform interface for all CLI operations.
    Each command encapsulates a specific operation (analyze, batch, interactive, etc.)
    and can be executed independently with its own validation and execution logic.

    Design principles:
    - Single Responsibility: Each command handles one specific CLI operation
    - Open/Closed: New commands can be added without modifying existing code
    - Dependency Inversion: Commands depend on abstractions (CommandContext) not concretions
    """

    def __init__(self, context: CommandContext | None = None):
        """
        Initialize command with optional context.

        Args:
            context: Shared command context for dependencies and configuration
        """
        self._context = context

    @abstractmethod
    def execute(self, args: dict[str, Any]) -> int:
        """
        Execute the command with provided arguments.

        This method must be implemented by all concrete command classes.
        It encapsulates the complete execution logic for the command.

        Args:
            args: Dictionary of command arguments (from Click)

        Returns:
            Exit code (0 for success, non-zero for failure)

        Raises:
            Exception: Command-specific exceptions based on execution errors
        """
        pass

    @property
    def context(self) -> CommandContext:
        """
        Get command context, creating a default if not set.

        Returns:
            CommandContext instance
        """
        if self._context is None:
            self._context = CommandContext.create()
        return self._context

    @context.setter
    def context(self, value: CommandContext) -> None:
        """
        Set command context.

        Args:
            value: CommandContext instance to set
        """
        self._context = value

    def _get_config(self, config_path: str | None = None) -> Config:
        """
        Load configuration from path or use context config.

        Args:
            config_path: Optional path to custom config file

        Returns:
            Config object instance
        """
        if config_path:
            return Config(config_path)
        if self.context.config is None:
            return Config()
        return self.context.config

    def _setup_analysis_options(
        self,
        yara: str | None = None,
        xor: str | None = None,
    ) -> dict[str, Any]:
        """
        Configure analysis options dictionary.

        Consolidates optional analysis parameters into a standardized dictionary
        format expected by inspector.analyze().

        Args:
            yara: Path to custom YARA rules directory
            xor: XOR key for string search

        Returns:
            Dictionary of analysis options
        """
        options = {}

        if yara:
            options["yara_rules_dir"] = yara

        if xor:
            options["xor_search"] = xor

        return options
