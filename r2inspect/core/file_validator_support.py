#!/usr/bin/env python3
"""Support helpers for file validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def file_exists(file_path: Path, filename: str, logger: Any) -> bool:
    if file_path.exists():
        if file_path.is_file():
            return True
        logger.error("Path is not a file: %s", filename)
        return False

    logger.error("File does not exist: %s", filename)
    return False


def is_size_valid(
    file_size: int, filename: str, min_executable_size_bytes: int, logger: Any
) -> bool:
    if file_size == 0:
        logger.error("File is empty: %s", filename)
        return False

    if file_size < min_executable_size_bytes:
        logger.error("File too small for analysis (%s bytes): %s", file_size, filename)
        return False

    return True


def within_memory_limits(file_size: int, check_memory_limits: Any, logger: Any) -> bool:
    if check_memory_limits(file_size_bytes=file_size):
        return True

    logger.error("File exceeds memory limits: %.1fMB", file_size / 1024 / 1024)
    return False


def is_readable(file_path: Path, filename: str, min_header_size_bytes: int, logger: Any) -> bool:
    try:
        with open(file_path, "rb") as f:
            header = f.read(min_header_size_bytes)
            if len(header) < 4:
                logger.error("Cannot read file header: %s", filename)
                return False
    except OSError as e:
        logger.error("File access error: %s - %s", filename, e)
        return False

    return True
