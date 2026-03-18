#!/usr/bin/env python3
"""r2pipe session management helpers."""

import os
import platform
from types import TracebackType
from typing import Any, Literal

import psutil
import r2pipe

from ..domain.constants import (
    HUGE_FILE_THRESHOLD_MB,
    LARGE_FILE_THRESHOLD_MB,
    MIN_INFO_RESPONSE_LENGTH,
    TEST_HUGE_FILE_THRESHOLD_MB,
    TEST_LARGE_FILE_THRESHOLD_MB,
    TEST_R2_ANALYSIS_TIMEOUT,
    TEST_R2_CMD_TIMEOUT,
    TEST_R2_OPEN_TIMEOUT,
)
from ..error_handling.classifier import ErrorCategory, ErrorSeverity, error_handler
from ..infrastructure.logging import get_logger
from .r2_session_cleanup import (
    detect_fat_macho_arches as _detect_fat_macho_arches_impl,
    force_close_process as _force_close_process_impl,
    reopen_safe_mode as _reopen_safe_mode_impl,
    select_r2_flags as _select_r2_flags_impl,
    terminate_radare2_processes as _terminate_radare2_processes_impl,
)
from .r2_session_timeouts import (
    open_with_timeout as _open_with_timeout_impl,
    perform_initial_analysis as _perform_initial_analysis_impl,
    run_basic_info_check as _run_basic_info_check_impl,
    run_cmd_with_timeout as _run_cmd_with_timeout_impl,
)

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
        self._test_mode = os.environ.get("R2INSPECT_TEST_MODE", "").lower() in {
            "1",
            "true",
            "yes",
        }

    @property
    def _is_test_mode(self) -> bool:
        """Check if running in test mode for resource-constrained execution."""
        env_value = os.environ.get("R2INSPECT_TEST_MODE", "").lower()
        if env_value in {"1", "true", "yes"}:
            return True
        if env_value in {"0", "false", "no"}:
            return False
        return self._test_mode

    def _get_open_timeout(self) -> float:
        """Return appropriate r2pipe.open() timeout based on mode."""
        return TEST_R2_OPEN_TIMEOUT if self._is_test_mode else 30.0

    def _get_cmd_timeout(self) -> float:
        """Return appropriate command timeout based on mode."""
        return TEST_R2_CMD_TIMEOUT if self._is_test_mode else 10.0

    def _get_analysis_timeout(self, full_analysis: bool = False) -> float:
        """Return appropriate analysis timeout based on mode."""
        if self._is_test_mode:
            return float(TEST_R2_ANALYSIS_TIMEOUT)
        return 60.0 if full_analysis else 30.0

    def _get_large_file_threshold(self) -> float:
        """Return large file threshold based on mode."""
        if self._is_test_mode:
            return float(TEST_LARGE_FILE_THRESHOLD_MB)
        return float(LARGE_FILE_THRESHOLD_MB)

    def _get_huge_file_threshold(self) -> float:
        """Return huge file threshold based on mode."""
        if self._is_test_mode:
            return float(TEST_HUGE_FILE_THRESHOLD_MB)
        return float(HUGE_FILE_THRESHOLD_MB)

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
            logger.debug("Opening file with radare2: %s", self.filename)
            logger.debug("Calling r2pipe.open()...")

            flags = self._select_r2_flags()

            self.r2 = self._open_with_timeout(flags, timeout=self._get_open_timeout())
            logger.debug("r2pipe.open() completed successfully")
            self._cleanup_required = True

            if not self._run_basic_info_check():
                logger.warning("Basic r2 info check timed out; reopening in safe mode.")
                return self._reopen_safe_mode()

            if not self._perform_initial_analysis(file_size_mb):
                logger.warning("Initial r2 analysis timed out; reopening in safe mode.")
                return self._reopen_safe_mode()

            return self.r2

        except Exception as e:
            logger.error("Failed to initialize r2pipe: %s", e)
            if self.r2:
                self.close()
            raise

    def _select_r2_flags(self) -> list[str]:
        return _select_r2_flags_impl(self, logger=logger)

    def _detect_fat_macho_arches(self) -> set[str]:
        return _detect_fat_macho_arches_impl(self.filename)

    def _open_with_timeout(self, flags: list[str], timeout: float) -> Any:
        return _open_with_timeout_impl(self, flags, timeout, logger=logger)

    def _terminate_radare2_processes(self) -> None:
        _terminate_radare2_processes_impl(self.filename)

    def _reopen_safe_mode(self) -> Any:
        return _reopen_safe_mode_impl(self)

    def _run_cmd_with_timeout(self, command: str, timeout: float) -> bool:
        return _run_cmd_with_timeout_impl(self, command, timeout, logger=logger)

    def _run_basic_info_check(self) -> bool:
        return _run_basic_info_check_impl(
            self, logger=logger, min_info_response_length=MIN_INFO_RESPONSE_LENGTH
        )

    def _perform_initial_analysis(self, file_size_mb: float) -> bool:
        return _perform_initial_analysis_impl(self, file_size_mb, logger=logger)

    def close(self) -> None:
        """Clean up r2pipe instance."""
        r2_instance = self.r2
        if r2_instance and self._cleanup_required:
            try:
                logger.debug("Cleaning up r2pipe instance")
                r2_instance.quit()
            except Exception as e:
                logger.debug("Error during r2pipe cleanup: %s", e)
            finally:
                self._force_close_process(r2_instance)
                self._cleanup_required = False
                self.r2 = None

    @staticmethod
    def _force_close_process(r2_instance: Any) -> None:
        _force_close_process_impl(r2_instance)

    def __del__(self) -> None:
        """Destructor fallback for sessions that outlive their test scope."""
        try:
            self.close()
        except Exception as e:
            logger.debug("Error closing R2Session in __del__: %s", e)

    @property
    def is_open(self) -> bool:
        """Check if the r2pipe session is open."""
        return self.r2 is not None and self._cleanup_required

    def __enter__(self) -> "R2Session":
        """Context manager entry."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> Literal[False]:
        """Context manager exit with cleanup."""
        self.close()
        return False


__all__ = ["R2Session"]
