#!/usr/bin/env python3
"""Pure validation rules for CLI inputs."""

from __future__ import annotations

import os
from pathlib import Path

from ..security.validators import FileValidator


def validate_file_input(
    filename: str | None,
    *,
    file_validator_cls: type[FileValidator] = FileValidator,
) -> list[str]:
    errors: list[str] = []
    if filename:
        try:
            validator = file_validator_cls()
            validated_path = validator.validate_path(filename, check_exists=True)
            if os.getenv("R2INSPECT_TEST_RAISE_FILE_ERROR"):
                raise OSError("Simulated file access error")
            if not validated_path.is_file():
                errors.append(f"Path is not a regular file: {filename}")
            else:
                file_size = validated_path.stat().st_size
                if file_size == 0:
                    errors.append(f"File is empty: {filename}")
                elif file_size > 1024 * 1024 * 1024:
                    errors.append(f"File too large (>1GB): {filename}")
        except ValueError as exc:
            errors.append(f"File path security validation failed: {exc}")
        except (OSError, RuntimeError) as exc:
            errors.append(f"File access error: {exc}")
    return errors


def validate_batch_input(
    batch: str | None,
    *,
    file_validator_cls: type[FileValidator] = FileValidator,
) -> list[str]:
    errors: list[str] = []
    if batch:
        try:
            validator = file_validator_cls()
            validated_path = validator.validate_path(batch, check_exists=True)
            if not validated_path.is_dir():
                errors.append(f"Batch path is not a directory: {batch}")
            if os.getenv("R2INSPECT_TEST_RAISE_BATCH_ERROR"):
                raise OSError("Simulated batch access error")
        except ValueError as exc:
            errors.append(f"Batch directory security validation failed: {exc}")
        except (OSError, RuntimeError) as exc:
            errors.append(f"Batch directory access error: {exc}")
    return errors


def validate_output_input(output: str | None) -> list[str]:
    errors: list[str] = []
    if output:
        output_path = Path(output)
        if output_path.exists() and output_path.is_file():
            try:
                with open(output_path, "a"):
                    pass
            except PermissionError:
                errors.append(f"Cannot write to output file: {output}")
        elif output_path.suffix == "":
            parent = output_path.parent
            if parent.exists() and not parent.is_dir():
                errors.append(f"Output parent path is not a directory: {parent}")
    return errors


def validate_yara_input(yara: str | None) -> list[str]:
    errors: list[str] = []
    if yara:
        yara_path = Path(yara)
        if not yara_path.exists():
            errors.append(f"YARA rules directory does not exist: {yara}")
        elif not yara_path.is_dir():
            errors.append(f"YARA path is not a directory: {yara}")
    return errors


def validate_config_input(config: str | None) -> list[str]:
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
    errors: list[str] = []
    if extensions:
        for ext in (part.strip() for part in extensions.split(",")):
            if not ext.replace(".", "").replace("_", "").replace("-", "").isalnum():
                errors.append(f"Invalid file extension: {ext}")
            if len(ext) > 10:
                errors.append(f"File extension too long: {ext}")
    return errors


def validate_threads_input(threads: int | None) -> list[str]:
    errors: list[str] = []
    if threads is not None:
        if not isinstance(threads, int) or threads < 1:
            errors.append("Threads must be a positive integer")
        elif threads > 50:
            errors.append("Too many threads (max 50)")
    return errors
