#!/usr/bin/env python3
"""File validation used before binary analysis begins."""

from pathlib import Path

from ..infrastructure.logging import get_logger
from ..infrastructure.memory import check_memory_limits
from ..domain.constants import MIN_EXECUTABLE_SIZE_BYTES, MIN_HEADER_SIZE_BYTES
from .file_validator_support import (
    file_exists as _file_exists_impl,
    is_readable as _is_readable_impl,
    is_size_valid as _is_size_valid_impl,
    within_memory_limits as _within_memory_limits_impl,
)

logger = get_logger(__name__)


class FileValidator:
    """Validate file existence, size, memory budget and readability."""

    def __init__(self, filename: str | Path):
        """Store the target file and initialize cached validation state."""
        self.filename = str(filename)
        self.file_path = Path(filename)
        self._validated: bool = False
        self._validation_result: bool = False

    def validate(self) -> bool:
        """Run the full validation sequence once and cache the result."""
        if self._validated:
            return self._validation_result

        try:
            if not self._file_exists():
                return self._fail_validation()

            file_size = self._file_size_bytes()
            if not self._is_size_valid(file_size):
                return self._fail_validation()

            if not self._within_memory_limits(file_size):
                return self._fail_validation()

            self._validation_result = self._is_readable()
            self._validated = True
            return self._validation_result

        except Exception as e:  # pragma: no cover
            logger.error("Error validating file %s: %s", self.filename, e)
            return self._fail_validation()

    def _fail_validation(self) -> bool:
        """Cache and return a failed validation result."""
        self._validation_result = False
        self._validated = True
        return False

    def _file_exists(self) -> bool:
        return _file_exists_impl(self.file_path, self.filename, logger)

    def _file_size_bytes(self) -> int:
        """Return the file size in bytes."""
        return self.file_path.stat().st_size

    def _file_size_mb(self) -> float:
        """Return the file size in megabytes."""
        return self._file_size_bytes() / (1024 * 1024)

    def _is_size_valid(self, file_size: int) -> bool:
        return _is_size_valid_impl(file_size, self.filename, MIN_EXECUTABLE_SIZE_BYTES, logger)

    def _within_memory_limits(self, file_size: int) -> bool:
        return _within_memory_limits_impl(file_size, check_memory_limits, logger)

    def _is_readable(self) -> bool:
        return _is_readable_impl(self.file_path, self.filename, MIN_HEADER_SIZE_BYTES, logger)


__all__ = ["FileValidator"]
