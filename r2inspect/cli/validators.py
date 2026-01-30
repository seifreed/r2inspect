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
    """
    Validate file input parameter with security checks.

    Security: Prevents path traversal attacks (CWE-22) and symlink attacks (CWE-59) by:
    1. Resolving the canonical absolute path
    2. Detecting symlinks and path traversal attempts
    3. Validating file size and accessibility
    4. Rejecting paths with dangerous characters

    Args:
        filename: User-provided file path

    Returns:
        List of validation error messages (empty if valid)
    """
    errors: list[str] = []
    if filename:
        try:
            # SECURITY FIX: Use FileValidator to prevent path traversal and symlink attacks
            # This resolves symlinks, validates path safety, and prevents directory traversal
            validator = FileValidator()
            validated_path = validator.validate_path(filename, check_exists=True)

            # Additional validations after path is secured
            if not validated_path.is_file():
                errors.append(f"Path is not a regular file: {filename}")
            else:
                # Check file size constraints
                file_size = validated_path.stat().st_size
                if file_size == 0:
                    errors.append(f"File is empty: {filename}")
                elif file_size > 1024 * 1024 * 1024:  # 1GB limit
                    errors.append(f"File too large (>1GB): {filename}")

        except ValueError as e:
            # FileValidator raises ValueError for security violations
            errors.append(f"File path security validation failed: {e}")
        except (OSError, RuntimeError) as e:
            # File system errors
            errors.append(f"File access error: {e}")

    return errors


def validate_batch_input(batch: str | None) -> list[str]:
    """
    Validate batch directory input with security checks.

    Security: Prevents path traversal and symlink attacks in batch processing.

    Args:
        batch: User-provided directory path

    Returns:
        List of validation error messages (empty if valid)
    """
    errors: list[str] = []
    if batch:
        try:
            # SECURITY: Validate directory path to prevent traversal attacks
            validator = FileValidator()
            validated_path = validator.validate_path(batch, check_exists=True)

            if not validated_path.is_dir():
                errors.append(f"Batch path is not a directory: {batch}")

        except ValueError as e:
            errors.append(f"Batch directory security validation failed: {e}")
        except (OSError, RuntimeError) as e:
            errors.append(f"Batch directory access error: {e}")

    return errors


def validate_output_input(output: str | None) -> list[str]:
    """
    Validate output path input.

    Args:
        output: Output path (file or directory)

    Returns:
        List of validation error messages (empty if valid)
    """
    errors: list[str] = []
    if output:
        output_path = Path(output)
        if output_path.exists() and output_path.is_file():
            try:
                with open(output_path, "a"):
                    # Test file writability by opening in append mode
                    # This ensures we have write permissions without modifying the file
                    pass
            except PermissionError:
                errors.append(f"Cannot write to output file: {output}")
        elif output_path.suffix == "":
            parent = output_path.parent
            if parent.exists() and not parent.is_dir():
                errors.append(f"Output parent path is not a directory: {parent}")
    return errors


def validate_yara_input(yara: str | None) -> list[str]:
    """
    Validate YARA rules directory input.

    Args:
        yara: YARA rules directory path

    Returns:
        List of validation error messages (empty if valid)
    """
    errors: list[str] = []
    if yara:
        yara_path = Path(yara)
        if not yara_path.exists():
            errors.append(f"YARA rules directory does not exist: {yara}")
        elif not yara_path.is_dir():
            errors.append(f"YARA path is not a directory: {yara}")
    return errors


def validate_config_input(config: str | None) -> list[str]:
    """
    Validate config file input.

    Args:
        config: Config file path

    Returns:
        List of validation error messages (empty if valid)
    """
    errors: list[str] = []
    if config:
        config_path = Path(config)
        if not config_path.exists():
            errors.append(f"Config file does not exist: {config}")
        elif not config_path.is_file():
            errors.append(f"Config path is not a file: {config}")
        elif config_path.suffix.lower() not in [".json", ".yaml", ".yml", ".toml"]:
            errors.append(f"Config file must be JSON, YAML, or TOML: {config}")
    return errors


def validate_extensions_input(extensions: str | None) -> list[str]:
    """
    Validate file extensions input.

    Args:
        extensions: Comma-separated file extensions

    Returns:
        List of validation error messages (empty if valid)
    """
    errors: list[str] = []
    if extensions:
        ext_list = [ext.strip() for ext in extensions.split(",")]
        for ext in ext_list:
            if not ext.replace(".", "").replace("_", "").replace("-", "").isalnum():
                errors.append(f"Invalid file extension: {ext}")
            if len(ext) > 10:
                errors.append(f"File extension too long: {ext}")
    return errors


def validate_threads_input(threads: int | None) -> list[str]:
    """
    Validate threads input.

    Args:
        threads: Number of threads

    Returns:
        List of validation error messages (empty if valid)
    """
    errors: list[str] = []
    if threads is not None:
        if not isinstance(threads, int) or threads < 1:
            errors.append("Threads must be a positive integer")
        elif threads > 50:
            errors.append("Too many threads (max 50)")
    return errors


def display_validation_errors(validation_errors: list[str]) -> None:
    """
    Display validation errors and exit.

    Args:
        validation_errors: List of error messages
    """
    for error in validation_errors:
        console.print(f"[red]Error: {error}[/red]")


def validate_input_mode(filename: str | None, batch: str | None) -> None:
    """
    Validate that either filename or batch mode is provided (not both).

    Args:
        filename: Single file to analyze
        batch: Batch directory

    Exits if validation fails.
    """
    if not filename and not batch:
        console.print("[red]Error: Must provide either a filename or --batch directory[/red]")
        sys.exit(1)

    if filename and batch:
        console.print("[red]Error: Cannot use both filename and --batch mode simultaneously[/red]")
        sys.exit(1)

    if filename:
        validate_single_file(filename)


def validate_single_file(filename: str) -> None:
    """
    Validate that the single file exists and is valid.

    Args:
        filename: File to validate

    Exits if validation fails.
    """
    file_path = Path(filename)
    if not file_path.exists():
        console.print(f"[red]Error: File does not exist: {filename}[/red]")
        console.print(
            "[yellow]Please provide the full path to the file you want to analyze[/yellow]"
        )
        sys.exit(1)
    elif not file_path.is_file():
        console.print(f"[red]Error: Path is not a file: {filename}[/red]")
        sys.exit(1)


def sanitize_xor_string(xor_input: str | None) -> str | None:
    """
    Sanitize XOR search string input.

    Args:
        xor_input: XOR string to sanitize

    Returns:
        Sanitized XOR string or None if invalid
    """
    if not xor_input:
        return None

    # Remove potentially dangerous characters
    safe_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-.")
    sanitized = "".join(c for c in xor_input if c in safe_chars)

    # Limit length
    if len(sanitized) > 100:
        sanitized = sanitized[:100]

    return sanitized if sanitized else None


def handle_xor_input(xor: str | None) -> str | None:
    """
    Handle and sanitize XOR input with warning message.

    Args:
        xor: XOR string input

    Returns:
        Sanitized XOR string or None
    """
    sanitized_xor = sanitize_xor_string(xor)
    if xor and not sanitized_xor:
        console.print(
            "[yellow]Warning: XOR string contains invalid characters and was filtered[/yellow]"
        )
    return sanitized_xor
