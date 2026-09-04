#!/usr/bin/env python3
"""Click-based command-line entry point for r2inspect.
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

import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import click

from pathlib import Path

from .application.explain import explain_file, format_explanation
from .cli.analysis_runner import handle_main_error
from .cli.cli_entry import (
    build_context as _build_context_impl,
    build_dispatch,
    execute_list_yara,
    execute_version,
)
from .cli.commands import CommandContext
from .cli.display import console, print_banner
from .cli.validators import (
    display_validation_errors,
    handle_xor_input,
    validate_legacy_json,
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
    profile: str = "standard"
    explain: str | None = None
    backend: str = "r2"
    consensus_backend: str = "pe-core"
    legacy_json: bool = False
    cache: str | None = None
    resume: bool = False


def main(
    *,
    run_cli_fn: Callable[[CLIArgs], None] | None = None,
    error_handler_fn: Callable[[Exception, bool], None] | None = None,
    **kwargs: Any,
) -> None:
    """Run the CLI with injectable dispatch and error handling."""
    args: CLIArgs | None = None
    try:
        args = CLIArgs(**kwargs)
        (run_cli_fn or run_cli)(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted by user[/yellow]")
        sys.exit(1)

    except Exception as e:
        (error_handler_fn or handle_main_error)(e, args.verbose if args else False)


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
@click.option("--legacy-json", is_flag=True, help="Deprecated 3.x JSON (requires --json)")
@click.option("--cache", type=click.Path(), help="SQLite cache for batch results")
@click.option("--resume", is_flag=True, help="Reuse valid entries from --cache")
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
@click.option("--explain", help="Explain a finding ID or rule ID from a report JSON file")
@click.option("--backend", default="r2", show_default=True, help="Analysis backend")
@click.option(
    "--consensus-backend",
    default="pe-core",
    show_default=True,
    help="Backend compared in consensus mode",
)
@click.option(
    "--profile",
    type=click.Choice(["fast", "standard", "deep", "forensic"], case_sensitive=False),
    default="standard",
    show_default=True,
    help="Analysis cost profile",
)
@click.option(
    "--threads",
    default=10,
    type=click.IntRange(1, 50),
    help="Number of parallel threads for batch processing (1-50, default: 10)",
)
def cli(**kwargs: Any) -> None:
    """Click-based CLI entry point."""
    main(**kwargs)


def run_cli(
    args: CLIArgs,
    *,
    dispatch_fn: Callable[[CommandContext, CLIArgs], None] | None = None,
    list_yara_fn: Callable[[str | None, str | None], None] | None = None,
) -> None:
    if args.version:
        execute_version()

    if args.explain:
        if not args.filename:
            raise click.UsageError("--explain requires a report JSON path")
        print(format_explanation(explain_file(Path(args.filename), args.explain)), end="")
        return

    validate_legacy_json(args.legacy_json, args.output_json)

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
        if args.output_json:
            print(json.dumps({"error": "; ".join(validation_errors)}))
        else:
            display_validation_errors(validation_errors)
        sys.exit(1)

    if args.list_yara:
        (list_yara_fn or execute_list_yara)(args.config, args.yara)

    validate_input_mode(args.filename, args.batch)

    if not args.output_json and not args.output_csv and not args.quiet:
        print_banner()

    sanitized_xor = handle_xor_input(args.xor)
    context = _build_context(args.verbose, args.quiet, args.batch)
    args_with_xor = CLIArgs(**{**args.__dict__, "xor": sanitized_xor})
    (dispatch_fn or _dispatch_command)(context, args_with_xor)


def _build_context(
    verbose: bool,
    quiet: bool,
    batch: str | None,
    *,
    context_factory: Callable[..., CommandContext] | None = None,
) -> CommandContext:
    return _build_context_impl(verbose, quiet, batch, context_factory=context_factory)


def _dispatch_command(
    context: CommandContext,
    args: CLIArgs,
    build_dispatch_fn: Callable[[CommandContext, CLIArgs], Any] | None = None,
) -> None:
    dispatch = (build_dispatch_fn or build_dispatch)(context, args)
    sys.exit(dispatch.command.execute(dispatch.payload))


# Backwards-compat aliases for tests that import the private names.
_execute_list_yara = execute_list_yara
_execute_version = execute_version


if __name__ == "__main__":
    main()
