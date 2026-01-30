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
    "validators": ("r2inspect.cli.validators", None),
    "display": ("r2inspect.cli.display", None),
    "batch_processing": ("r2inspect.cli.batch_processing", None),
    "batch_output": ("r2inspect.cli.batch_output", None),
    "analysis_runner": ("r2inspect.cli.analysis_runner", None),
    "interactive": ("r2inspect.cli.interactive", None),
    # Exported utilities
    "create_batch_summary": ("r2inspect.cli.batch_output", "create_batch_summary"),
    "display_batch_results": ("r2inspect.cli.batch_processing", "display_batch_results"),
    "display_no_files_message": ("r2inspect.cli.batch_processing", "display_no_files_message"),
    "find_files_to_process": ("r2inspect.cli.batch_processing", "find_files_to_process"),
    "process_files_parallel": ("r2inspect.cli.batch_processing", "process_files_parallel"),
    "setup_batch_output_directory": (
        "r2inspect.cli.batch_processing",
        "setup_batch_output_directory",
    ),
    "setup_rate_limiter": ("r2inspect.cli.batch_processing", "setup_rate_limiter"),
    "display_results": ("r2inspect.cli.display", "display_results"),
    "display_error_statistics": ("r2inspect.cli.display", "display_error_statistics"),
    "display_performance_statistics": ("r2inspect.cli.display", "display_performance_statistics"),
    "has_circuit_breaker_data": ("r2inspect.cli.analysis_runner", "has_circuit_breaker_data"),
    # Commands
    "Command": ("r2inspect.cli.commands", "Command"),
    "CommandContext": ("r2inspect.cli.commands", "CommandContext"),
    "AnalyzeCommand": ("r2inspect.cli.commands", "AnalyzeCommand"),
    "BatchCommand": ("r2inspect.cli.commands", "BatchCommand"),
    "InteractiveCommand": ("r2inspect.cli.commands", "InteractiveCommand"),
    "VersionCommand": ("r2inspect.cli.commands", "VersionCommand"),
    "ConfigCommand": ("r2inspect.cli.commands", "ConfigCommand"),
}


def __getattr__(name: str):
    if name not in _LAZY_ATTRS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr = _LAZY_ATTRS[name]
    module = importlib.import_module(module_name)
    return module if attr is None else getattr(module, attr)


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + list(_LAZY_ATTRS.keys()))


def main():  # Entry point shim for console_scripts
    """CLI entry point compatible with pyproject console script.

    Delegates to the Click-based CLI defined in r2inspect.cli_main.
    This shim avoids import path churn and preserves existing entry points.
    """
    from ..cli_main import cli as _cli

    _cli()
