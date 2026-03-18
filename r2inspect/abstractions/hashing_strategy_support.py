#!/usr/bin/env python3
"""Helper operations for hashing strategy facades."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from ..domain.results import HashResult


def validate_strategy_init(filepath: str, max_file_size: int, min_file_size: int) -> Path:
    if not filepath:
        raise ValueError("filepath cannot be empty")
    if max_file_size <= 0 or min_file_size < 0:
        raise ValueError("File size limits must be positive")
    if min_file_size > max_file_size:
        raise ValueError("min_file_size cannot exceed max_file_size")
    return Path(filepath)


def run_hash_analysis(strategy: Any) -> dict[str, Any]:
    start_time = time.time()
    result = HashResult(hash_type=strategy._get_hash_type())
    try:
        validation_error = strategy._validate_file()
        if validation_error:
            result.error = validation_error
            result.execution_time = time.time() - start_time
            return result.to_dict()
        result.file_size = strategy._filepath.stat().st_size
        library_available, error_message = strategy._check_library_availability()
        if not library_available:
            result.error = error_message or "Required library not available"
            result.execution_time = time.time() - start_time
            return result.to_dict()
        result.available = True
        hash_value, method_used, error = strategy._calculate_hash()
        if error:
            result.error = error
        else:
            result.hash_value = hash_value
            result.method_used = method_used
    except Exception as exc:
        result.error = f"Unexpected error in {strategy._get_hash_type()} analysis: {str(exc)}"
    finally:
        result.execution_time = time.time() - start_time
    return result.to_dict()


def validate_hash_file(path: Path, min_file_size: int, max_file_size: int) -> str | None:
    try:
        if not path.exists():
            return f"File does not exist: {path}"
        if not path.is_file():
            return f"Path is not a regular file: {path}"
        file_size = path.stat().st_size
        if file_size < min_file_size:
            return (
                f"File too small for analysis ({file_size} bytes, "
                f"minimum: {min_file_size} bytes)"
            )
        if file_size > max_file_size:
            return (
                f"File too large for analysis ({file_size} bytes, "
                f"maximum: {max_file_size} bytes)"
            )
    except OSError as exc:
        return f"Cannot access file statistics: {str(exc)}"
    if not os.access(path, os.R_OK):
        return f"File is not readable: {path}"
    return None
