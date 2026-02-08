#!/usr/bin/env python3
"""
r2inspect CLI Package

Command-line interface for r2inspect malware analysis tool.
Includes modular utility functions extracted from cli_utils.py.

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

import importlib
from typing import Any

MODULE_BATCH_PROCESSING = "r2inspect.cli.batch_processing"
MODULE_BATCH_OUTPUT = "r2inspect.cli.batch_output"
MODULE_COMMANDS = "r2inspect.cli.commands"
MODULE_DISPLAY = "r2inspect.cli.display"
MODULE_INTERACTIVE = "r2inspect.cli.interactive"
MODULE_RUNNER = "r2inspect.cli.analysis_runner"
MODULE_VALIDATORS = "r2inspect.cli.validators"

__all__ = [
    # Commands
    "Command",
    "CommandContext",
    "AnalyzeCommand",
    "BatchCommand",
    "InteractiveCommand",
    "VersionCommand",
    "ConfigCommand",
    # Utility modules
    "validators",
    "display",
    "batch_processing",
    "batch_output",
    "analysis_runner",
    "interactive",
    # Exported utilities
    "create_batch_summary",
    "display_batch_results",
    "display_no_files_message",
    "find_files_to_process",
    "process_files_parallel",
    "setup_batch_output_directory",
    "setup_rate_limiter",
    "display_results",
    "display_error_statistics",
    "display_performance_statistics",
    "has_circuit_breaker_data",
]


_LAZY_ATTRS: dict[str, tuple[str, str | None]] = {
    # Utility modules
    "validators": (MODULE_VALIDATORS, None),
    "display": (MODULE_DISPLAY, None),
    "batch_processing": (MODULE_BATCH_PROCESSING, None),
    "batch_output": (MODULE_BATCH_OUTPUT, None),
    "analysis_runner": (MODULE_RUNNER, None),
    "interactive": (MODULE_INTERACTIVE, None),
    # Exported utilities
    "create_batch_summary": (MODULE_BATCH_OUTPUT, "create_batch_summary"),
    "display_batch_results": (MODULE_BATCH_PROCESSING, "display_batch_results"),
    "display_no_files_message": (MODULE_BATCH_PROCESSING, "display_no_files_message"),
    "find_files_to_process": (MODULE_BATCH_PROCESSING, "find_files_to_process"),
    "process_files_parallel": (MODULE_BATCH_PROCESSING, "process_files_parallel"),
    "setup_batch_output_directory": (
        MODULE_BATCH_PROCESSING,
        "setup_batch_output_directory",
    ),
    "setup_rate_limiter": (MODULE_BATCH_PROCESSING, "setup_rate_limiter"),
    "display_results": (MODULE_DISPLAY, "display_results"),
    "display_error_statistics": (MODULE_DISPLAY, "display_error_statistics"),
    "display_performance_statistics": (
        MODULE_DISPLAY,
        "display_performance_statistics",
    ),
    "has_circuit_breaker_data": (MODULE_RUNNER, "has_circuit_breaker_data"),
    # Commands
    "Command": (MODULE_COMMANDS, "Command"),
    "CommandContext": (MODULE_COMMANDS, "CommandContext"),
    "AnalyzeCommand": (MODULE_COMMANDS, "AnalyzeCommand"),
    "BatchCommand": (MODULE_COMMANDS, "BatchCommand"),
    "InteractiveCommand": (MODULE_COMMANDS, "InteractiveCommand"),
    "VersionCommand": (MODULE_COMMANDS, "VersionCommand"),
    "ConfigCommand": (MODULE_COMMANDS, "ConfigCommand"),
}


def __getattr__(name: str) -> Any:
    if name not in _LAZY_ATTRS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr = _LAZY_ATTRS[name]
    module = importlib.import_module(module_name)
    return module if attr is None else getattr(module, attr)


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + list(_LAZY_ATTRS.keys()))


def main() -> None:  # Entry point shim for console_scripts
    """CLI entry point compatible with pyproject console script.

    Delegates to the Click-based CLI defined in r2inspect.cli_main.
    This shim avoids import path churn and preserves existing entry points.
    """
    from ..cli_main import cli as _cli

    _cli()
