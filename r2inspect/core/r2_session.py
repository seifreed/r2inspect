#!/usr/bin/env python3
"""
r2inspect R2 Session Manager - r2pipe session management

This module provides the R2Session class which handles all r2pipe
connection management including initialization, analysis, and cleanup.

Copyright (C) 2025 Marc Rivero Lopez
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

from typing import Any, Literal

import r2pipe

from ..utils.error_handler import ErrorCategory, ErrorSeverity, error_handler
from ..utils.logger import get_logger
from .constants import HUGE_FILE_THRESHOLD_MB, LARGE_FILE_THRESHOLD_MB, MIN_INFO_RESPONSE_LENGTH

logger = get_logger(__name__)


class R2Session:
    """
    Manages r2pipe session lifecycle.

    This class encapsulates all r2pipe connection management including:
    - Opening connections with appropriate flags
    - Running initial analysis based on file size
    - Basic info verification
    - Session cleanup

    Attributes:
        filename: Path to the file being analyzed
        r2: The r2pipe instance (None until open() is called)
        _cleanup_required: Flag indicating if cleanup is needed
    """

    def __init__(self, filename: str):
        """
        Initialize R2Session with a file path.

        Args:
            filename: Path to the binary file to analyze
        """
        self.filename = filename
        self.r2: Any | None = None
        self._cleanup_required = False

    @error_handler(
        category=ErrorCategory.R2PIPE,
        severity=ErrorSeverity.CRITICAL,
        context={"phase": "initialization"},
        fallback_result=None,
    )
    def open(self, file_size_mb: float) -> Any:
        """
        Open r2pipe connection and perform initial analysis.

        Args:
            file_size_mb: Size of the file in megabytes

        Returns:
            The r2pipe instance

        Raises:
            RuntimeError: If r2pipe initialization or basic checks fail
        """
        try:
            logger.debug(f"Opening file with radare2: {self.filename}")
            logger.debug("Calling r2pipe.open()...")

            flags = self._select_r2_flags()

            self.r2 = r2pipe.open(self.filename, flags=flags)
            logger.debug("r2pipe.open() completed successfully")
            self._cleanup_required = True

            self._run_basic_info_check()
            self._perform_initial_analysis(file_size_mb)

            return self.r2

        except Exception as e:
            logger.error(f"Failed to initialize r2pipe: {e}")
            if self.r2:
                self.close()
            raise

    def _select_r2_flags(self) -> list[str]:
        """
        Return r2 flags for opening files.

        Returns:
            List of flags to pass to r2pipe.open()
        """
        # -2 flag disables stderr output from radare2
        return ["-2"]

    def _run_basic_info_check(self) -> None:
        """
        Run a basic info command to verify r2 responsiveness.

        Raises:
            RuntimeError: If r2 cannot properly analyze the file
        """
        try:
            if self.r2 is None:
                raise RuntimeError("r2pipe is not initialized")
            info_result = self.r2.cmd("i")
            if not info_result or len(info_result.strip()) < MIN_INFO_RESPONSE_LENGTH:
                logger.warning(f"r2 basic info command returned minimal data for {self.filename}")
        except Exception as e:
            logger.error(f"r2 basic info test failed: {e}")
            raise RuntimeError(f"r2 cannot properly analyze this file: {e}")

    def _perform_initial_analysis(self, file_size_mb: float) -> None:
        """
        Perform size-aware initial analysis with r2.

        Args:
            file_size_mb: Size of the file in megabytes
        """
        try:
            if self.r2 is None:
                raise RuntimeError("r2pipe is not initialized")

            if file_size_mb > HUGE_FILE_THRESHOLD_MB:
                logger.debug("Very large file detected, skipping automatic analysis...")
                return

            if file_size_mb > LARGE_FILE_THRESHOLD_MB:
                logger.debug("Large file detected, using standard analysis (aa command)...")
                self.r2.cmd("aa")
                logger.debug("Standard analysis (aa) completed")
                return

            logger.debug("Running full analysis (aaa command)...")
            self.r2.cmd("aaa")
            logger.debug("Full analysis (aaa) completed")

        except Exception as e:
            logger.warning(f"Analysis command failed, continuing with basic r2 setup: {e}")

    def close(self) -> None:
        """Clean up r2pipe instance."""
        if self.r2 and self._cleanup_required:
            try:
                logger.debug("Cleaning up r2pipe instance")
                self.r2.quit()
                self._cleanup_required = False
            except Exception as e:
                logger.debug(f"Error during r2pipe cleanup: {e}")
            finally:
                self.r2 = None

    @property
    def is_open(self) -> bool:
        """Check if the r2pipe session is open."""
        return self.r2 is not None and self._cleanup_required

    def __enter__(self) -> "R2Session":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> Literal[False]:
        """Context manager exit with cleanup."""
        self.close()
        return False


__all__ = ["R2Session"]
