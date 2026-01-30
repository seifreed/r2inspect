#!/usr/bin/env python3
"""
r2inspect File Validator - File validation logic for binary analysis

This module provides the FileValidator class which handles all file validation
operations before analysis begins.

Copyright (C) 2025 Marc Rivero Lopez
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

from pathlib import Path

from ..utils.logger import get_logger
from ..utils.memory_manager import check_memory_limits
from .constants import MIN_EXECUTABLE_SIZE_BYTES, MIN_HEADER_SIZE_BYTES

logger = get_logger(__name__)


class FileValidator:
    """
    Validates files before binary analysis.

    This class encapsulates all file validation logic including:
    - File existence checks
    - Size validation (minimum and maximum)
    - Memory limit verification
    - File readability checks

    Attributes:
        file_path: Pathlib Path object for the file
        filename: String representation of the file path
    """

    def __init__(self, filename: str | Path):
        """
        Initialize FileValidator with a file path.

        Args:
            filename: Path to the file to validate (string or Path object)
        """
        self.filename = str(filename)
        self.file_path = Path(filename)

    def validate(self) -> bool:
        """
        Perform complete file validation.

        Runs all validation checks in sequence:
        1. File existence
        2. File size validity
        3. Memory limits
        4. File readability

        Returns:
            True if all validations pass, False otherwise
        """
        try:
            if not self._file_exists():
                return False

            file_size = self._file_size_bytes()
            if not self._is_size_valid(file_size):
                return False

            if not self._within_memory_limits(file_size):
                return False

            return self._is_readable()

        except Exception as e:
            logger.error(f"Error validating file {self.filename}: {e}")
            return False

    def _file_exists(self) -> bool:
        """
        Check if the file exists.

        Returns:
            True if file exists, False otherwise
        """
        if self.file_path.exists():
            return True

        logger.error(f"File does not exist: {self.filename}")
        return False

    def _file_size_bytes(self) -> int:
        """
        Get the file size in bytes.

        Returns:
            File size in bytes
        """
        return self.file_path.stat().st_size

    def _file_size_mb(self) -> float:
        """
        Get the file size in megabytes.

        Returns:
            File size in megabytes
        """
        return self._file_size_bytes() / (1024 * 1024)

    def _is_size_valid(self, file_size: int) -> bool:
        """
        Check if the file size is valid for analysis.

        Args:
            file_size: Size of the file in bytes

        Returns:
            True if size is valid, False otherwise
        """
        if file_size == 0:
            logger.error(f"File is empty: {self.filename}")
            return False

        if file_size < MIN_EXECUTABLE_SIZE_BYTES:
            logger.error(f"File too small for analysis ({file_size} bytes): {self.filename}")
            return False

        return True

    def _within_memory_limits(self, file_size: int) -> bool:
        """
        Check if the file is within memory limits for analysis.

        Args:
            file_size: Size of the file in bytes

        Returns:
            True if within limits, False otherwise
        """
        if check_memory_limits(file_size_bytes=file_size):
            return True

        logger.error(f"File exceeds memory limits: {file_size / 1024 / 1024:.1f}MB")
        return False

    def _is_readable(self) -> bool:
        """
        Check if the file is readable and has a valid header.

        Returns:
            True if readable with valid header, False otherwise
        """
        try:
            with open(self.file_path, "rb") as f:
                header = f.read(MIN_HEADER_SIZE_BYTES)
                if len(header) < 4:
                    logger.error(f"Cannot read file header: {self.filename}")
                    return False
        except OSError as e:
            logger.error(f"File access error: {self.filename} - {e}")
            return False

        return True


__all__ = ["FileValidator"]
