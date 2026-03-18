#!/usr/bin/env python3
"""CLI entry orchestration helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .commands import AnalyzeCommand, BatchCommand, Command, CommandContext, InteractiveCommand


@dataclass
class CommandDispatch:
    command: Command
    payload: dict[str, Any]


def build_context(verbose: bool, quiet: bool, batch: str | None) -> CommandContext:
    return CommandContext.create(
        config=None, verbose=verbose, quiet=quiet, thread_safe=batch is not None
    )


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
