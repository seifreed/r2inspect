#!/usr/bin/env python3
"""Runtime helpers for command context and shared command setup."""

from __future__ import annotations

from typing import Any

from rich.console import Console

from ...config import Config
from ...infrastructure.logging import setup_logger


def create_command_context(
    *,
    config: Config | None,
    verbose: bool,
    quiet: bool,
    thread_safe: bool,
    configure_logging_levels: Any,
) -> tuple[Console, Any, Config]:
    console = Console()
    logger = setup_logger(thread_safe=thread_safe)
    configure_logging_levels(verbose, quiet)
    return console, logger, config or Config()


def resolve_config(context_config: Config | None, config_path: str | None) -> Config:
    if config_path:
        return Config(config_path)
    return context_config or Config()
