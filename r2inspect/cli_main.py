#!/usr/bin/env python3
"""
r2inspect CLI - Command Line Interface (Refactored with Command Pattern)

This module provides the Click-based CLI entry point for r2inspect.
Command execution logic has been extracted into modular command classes
following the Command Pattern for improved testability and maintainability.

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

import sys
from dataclasses import dataclass
from typing import Any

import click

# Import utility functions from modular CLI submodules
from .cli.analysis_runner import handle_main_error

# Import command implementations
from .cli.commands import (
    AnalyzeCommand,
    BatchCommand,
    Command,
    CommandContext,
    ConfigCommand,
    InteractiveCommand,
    VersionCommand,
)
from .cli.display import console, print_banner
from .cli.validators import (
    display_validation_errors,
    handle_xor_input,
    validate_input_mode,
    validate_inputs,
)


@dataclass
class CLIArgs:
    filename: str | None
    interactive: bool
    output_json: bool
    output_csv: bool
    output: str | None
    xor: str | None
    verbose: bool
    quiet: bool
    config: str | None
    yara: str | None
    batch: str | None
    extensions: str | None
    list_yara: bool
    threads: int
    version: bool


def main(**kwargs: Any):
    """
    r2inspect - Advanced malware analysis tool using radare2 and r2pipe.

    Modular Command Pattern implementation with delegated execution.
    """
    try:
        args = CLIArgs(**kwargs)
        run_cli(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted by user[/yellow]")
        sys.exit(1)

    except Exception as e:
        handle_main_error(e, args.verbose)


@click.command()
@click.argument("filename", type=click.Path(), required=False)
@click.option("-i", "--interactive", is_flag=True, help="Interactive mode")
@click.option(
    "-j",
    "--json",
    "output_json",
    is_flag=True,
    help="Full output analysis in JSON format",
)
@click.option("-c", "--csv", "output_csv", is_flag=True, help="Output analysis in CSV format")
@click.option("-o", "--output", help="Output file path or directory for batch mode")
@click.option("-x", "--xor", help="Search XORed string")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("--quiet", is_flag=True, help="Suppress r2pipe warnings and non-critical output")
@click.option("--config", help="Custom config file path")
@click.option("--yara", help="Custom YARA rules directory")
@click.option(
    "--batch",
    "--directory",
    type=click.Path(),
    help="Process all files in directory (batch mode - recursive by default)",
)
@click.option(
    "--extensions",
    help="File extensions to process in batch mode (comma-separated). Default: auto-detect executable files",
)
@click.option("--list-yara", is_flag=True, help="List all available YARA rules and exit")
@click.option("--version", is_flag=True, help="Show version information and exit")
@click.option(
    "--threads",
    default=10,
    type=click.IntRange(1, 50),
    help="Number of parallel threads for batch processing (1-50, default: 10)",
)
def cli(**kwargs: Any):
    """Click-based CLI entry point."""
    main(**kwargs)


def run_cli(args: CLIArgs) -> None:
    """Primary CLI workflow separated for clarity and testability."""
    if args.version:
        _execute_version()

    validation_errors = validate_inputs(
        args.filename,
        args.batch,
        args.output,
        args.yara,
        args.config,
        args.extensions,
        args.threads,
    )
    if validation_errors:
        display_validation_errors(validation_errors)
        sys.exit(1)

    if args.list_yara:
        _execute_list_yara(args.config, args.yara)

    validate_input_mode(args.filename, args.batch)

    if not args.output_json and not args.output_csv and not args.quiet:
        print_banner()

    sanitized_xor = handle_xor_input(args.xor)
    context = _build_context(args.verbose, args.quiet, args.batch)
    args_with_xor = CLIArgs(**{**args.__dict__, "xor": sanitized_xor})
    _dispatch_command(context, args_with_xor)


def _execute_list_yara(config: str | None, yara: str | None) -> None:
    """Run the ConfigCommand to list YARA rules and exit."""
    config_cmd = ConfigCommand()
    exit_code = config_cmd.execute(
        {
            "list_yara": True,
            "config": config,
            "yara": yara,
        }
    )
    sys.exit(exit_code)


def _execute_version() -> None:
    """Run the VersionCommand and exit."""
    version_cmd = VersionCommand()
    sys.exit(version_cmd.execute({}))


def _build_context(verbose: bool, quiet: bool, batch: str | None) -> CommandContext:
    """Construct a CommandContext with proper thread safety and logging."""
    return CommandContext.create(
        config=None,
        verbose=verbose,
        quiet=quiet,
        thread_safe=batch is not None,
    )


def _dispatch_command(
    context: CommandContext,
    args: CLIArgs,
) -> None:
    """Dispatch to the appropriate command based on CLI arguments."""
    command: Command
    if args.batch:
        command = BatchCommand(context)
        exit_code = command.execute(
            {
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
            }
        )
        sys.exit(exit_code)

    if args.interactive:
        command = InteractiveCommand(context)
        exit_code = command.execute(
            {
                "filename": args.filename,
                "config": args.config,
                "yara": args.yara,
                "xor": args.xor,
                "verbose": args.verbose,
            }
        )
        sys.exit(exit_code)

    command = AnalyzeCommand(context)
    exit_code = command.execute(
        {
            "filename": args.filename,
            "config": args.config,
            "yara": args.yara,
            "xor": args.xor,
            "output_json": args.output_json,
            "output_csv": args.output_csv,
            "output": args.output,
            "verbose": args.verbose,
            "threads": args.threads,
        }
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
