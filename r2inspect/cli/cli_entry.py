#!/usr/bin/env python3
"""CLI entry orchestration helpers."""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .commands import (
    AnalyzeCommand,
    BatchCommand,
    Command,
    CommandContext,
    ConfigCommand,
    InteractiveCommand,
    VersionCommand,
)


@dataclass
class CommandDispatch:
    command: Command
    payload: dict[str, Any]


def build_context(
    verbose: bool,
    quiet: bool,
    batch: str | None,
    *,
    context_factory: Callable[..., CommandContext] | None = None,
) -> CommandContext:
    """Build the command context.

    ``context_factory`` defaults to the real ``CommandContext.create``; tests
    inject a recording factory instead of patching the classmethod.
    """
    factory = context_factory or CommandContext.create
    return factory(config=None, verbose=verbose, quiet=quiet, thread_safe=batch is not None)


def build_dispatch(context: CommandContext, args: Any) -> CommandDispatch:
    if args.batch:
        return CommandDispatch(
            command=BatchCommand(context),
            payload={
                "batch": args.batch,
                "config": args.config,
                "yara": args.yara,
                "xor": args.xor,
                "output_json": args.output_json,
                "output_csv": args.output_csv,
                "output": args.output,
                "extensions": args.extensions,
                "threads": args.threads,
                "verbose": args.verbose,
                "quiet": args.quiet,
            },
        )
    if args.interactive:
        return CommandDispatch(
            command=InteractiveCommand(context),
            payload={
                "filename": args.filename,
                "config": args.config,
                "yara": args.yara,
                "xor": args.xor,
                "verbose": args.verbose,
            },
        )
    return CommandDispatch(
        command=AnalyzeCommand(context),
        payload={
            "filename": args.filename,
            "config": args.config,
            "yara": args.yara,
            "xor": args.xor,
            "output_json": args.output_json,
            "output_csv": args.output_csv,
            "output": args.output,
            "verbose": args.verbose,
            "threads": args.threads,
        },
    )


def execute_list_yara(config: str | None, yara: str | None) -> None:
    """Run the ConfigCommand to list YARA rules and exit."""
    config_cmd = ConfigCommand()
    sys.exit(
        config_cmd.execute(
            {
                "list_yara": True,
                "config": config,
                "yara": yara,
            }
        )
    )


def execute_version() -> None:
    """Run the VersionCommand and exit."""
    version_cmd = VersionCommand()
    sys.exit(version_cmd.execute({}))
