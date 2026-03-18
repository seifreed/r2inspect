#!/usr/bin/env python3
"""
r2inspect CLI Input Validation Module

Provides comprehensive input validation for CLI arguments with security checks.
Extracted from cli_utils.py for better modularity.

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
from pathlib import Path

from rich.console import Console

from ..security.validators import FileValidator
from . import validator_rules as _validator_rules
from .validator_runtime import handle_xor_input as _handle_xor_input_impl
from .validator_runtime import sanitize_xor_string as _sanitize_xor_string_impl
from .validator_runtime import validate_input_mode as _validate_input_mode_impl
from .validator_runtime import validate_single_file as _validate_single_file_impl

console = Console()


def validate_inputs(
    filename: str | None,
    batch: str | None,
    output: str | None,
    yara: str | None,
    config: str | None,
    extensions: str | None,
    threads: int | None,
) -> list[str]:
    """
    Validate all user inputs.

    Args:
        filename: File to analyze
        batch: Batch directory
        output: Output path
        yara: YARA rules directory
        config: Config file path
        extensions: File extensions
        threads: Number of threads

    Returns:
        List of validation error messages (empty if all valid)
    """
    errors: list[str] = []

    errors.extend(validate_file_input(filename))
    errors.extend(validate_batch_input(batch))
    errors.extend(validate_output_input(output))
    errors.extend(validate_yara_input(yara))
    errors.extend(validate_config_input(config))
    errors.extend(validate_extensions_input(extensions))
    errors.extend(validate_threads_input(threads))

    return errors


def validate_file_input(filename: str | None) -> list[str]:
    return _validator_rules.validate_file_input(filename, file_validator_cls=FileValidator)


def validate_batch_input(batch: str | None) -> list[str]:
    return _validator_rules.validate_batch_input(batch, file_validator_cls=FileValidator)


def validate_output_input(output: str | None) -> list[str]:
    return _validator_rules.validate_output_input(output)


def validate_yara_input(yara: str | None) -> list[str]:
    return _validator_rules.validate_yara_input(yara)


def validate_config_input(config: str | None) -> list[str]:
    return _validator_rules.validate_config_input(config)


def validate_extensions_input(extensions: str | None) -> list[str]:
    return _validator_rules.validate_extensions_input(extensions)


def validate_threads_input(threads: int | None) -> list[str]:
    return _validator_rules.validate_threads_input(threads)


def display_validation_errors(validation_errors: list[str]) -> None:
    """
    Display validation errors and exit.

    Args:
        validation_errors: List of error messages
    """
    for error in validation_errors:
        console.print(f"[red]Error: {error}[/red]")


def validate_input_mode(filename: str | None, batch: str | None) -> None:
    _validate_input_mode_impl(
        console,
        filename,
        batch,
        validate_single_file_fn=validate_single_file,
    )


def validate_single_file(filename: str) -> None:
    _validate_single_file_impl(console, filename)


def sanitize_xor_string(xor_input: str | None) -> str | None:
    return _sanitize_xor_string_impl(xor_input)


def handle_xor_input(xor: str | None) -> str | None:
    return _handle_xor_input_impl(
        console,
        xor,
        sanitize_xor_string_fn=sanitize_xor_string,
    )


__all__ = [
    "FileValidator",
    "console",
    "display_validation_errors",
    "handle_xor_input",
    "sanitize_xor_string",
    "validate_batch_input",
    "validate_config_input",
    "validate_extensions_input",
    "validate_file_input",
    "validate_input_mode",
    "validate_inputs",
    "validate_output_input",
    "validate_single_file",
    "validate_threads_input",
    "validate_yara_input",
]
