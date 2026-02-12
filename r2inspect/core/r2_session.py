#!/usr/bin/env python3
"""r2pipe session management helpers."""

import os
import platform
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from pathlib import Path
from types import TracebackType
from typing import Any, Literal

import psutil
import r2pipe

from ..utils.error_handler import ErrorCategory, ErrorSeverity, error_handler
from ..utils.logger import get_logger
from .constants import (
    HUGE_FILE_THRESHOLD_MB,
    LARGE_FILE_THRESHOLD_MB,
    MIN_INFO_RESPONSE_LENGTH,
    TEST_HUGE_FILE_THRESHOLD_MB,
    TEST_LARGE_FILE_THRESHOLD_MB,
    TEST_R2_ANALYSIS_TIMEOUT,
    TEST_R2_CMD_TIMEOUT,
    TEST_R2_OPEN_TIMEOUT,
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
            return TEST_R2_ANALYSIS_TIMEOUT
        return 60.0 if full_analysis else 30.0

    def _get_large_file_threshold(self) -> float:
        """Return large file threshold based on mode."""
        return TEST_LARGE_FILE_THRESHOLD_MB if self._is_test_mode else LARGE_FILE_THRESHOLD_MB

    def _get_huge_file_threshold(self) -> float:
        """Return huge file threshold based on mode."""
        return TEST_HUGE_FILE_THRESHOLD_MB if self._is_test_mode else HUGE_FILE_THRESHOLD_MB

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
            logger.error(f"Failed to initialize r2pipe: {e}")
            if self.r2:
                self.close()
            raise

    def _select_r2_flags(self) -> list[str]:
        """
        Return r2 flags for opening files.

        Returns:
            List of flags to pass to r2pipe.open()

        Flags used:
            -2: Disable stderr output from radare2
            -NN: Disable plugins (reduces memory overhead)
            -M: Disable demangling (reduces CPU usage, test mode only)
            -n: No analysis on load (used in safe mode fallback)
        """
        # -2 flag disables stderr output from radare2
        flags = ["-2"]

        # Test mode: add resource-saving flags
        if self._is_test_mode:
            # -M disables demangling to reduce CPU usage
            flags.append("-M")
            logger.debug("Test mode: enabled resource-saving r2 flags (-M)")

        fat_arches = self._detect_fat_macho_arches()
        if fat_arches:
            host = platform.machine().lower()
            if "arm" in host and "arm64" in fat_arches:
                flags += ["-a", "arm", "-b", "64"]
            elif "x86_64" in fat_arches:
                flags += ["-a", "x86", "-b", "64"]
            flags.append("-NN")
        if os.environ.get("R2INSPECT_DISABLE_PLUGINS", "").lower() in {"1", "true", "yes"}:
            # Only add -NN if not already present
            if "-NN" not in flags:
                flags.append("-NN")
        return flags

    def _detect_fat_macho_arches(self) -> set[str]:
        """Detect architectures for fat Mach-O binaries."""
        try:
            with open(self.filename, "rb") as f:
                header = f.read(8)
                if len(header) < 8:
                    return set()
                magic_be = struct.unpack(">I", header[:4])[0]
                if magic_be == 0xCAFEBABE:
                    endian = ">"
                elif magic_be == 0xBEBAFECA:
                    endian = "<"
                else:
                    return set()
                nfat_arch = struct.unpack(f"{endian}I", header[4:8])[0]
                arches: set[str] = set()
                for _ in range(nfat_arch):
                    entry = f.read(20)
                    if len(entry) < 20:
                        break
                    cputype = struct.unpack(f"{endian}I", entry[:4])[0]
                    if cputype == 0x01000007:
                        arches.add("x86_64")
                    elif cputype == 0x0100000C:
                        arches.add("arm64")
                return arches
        except Exception:
            return set()

    def _open_with_timeout(self, flags: list[str], timeout: float) -> Any:
        """Open r2pipe with a timeout and terminate hung radare2 processes."""
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(r2pipe.open, self.filename, flags=flags)
            try:
                return future.result(timeout=timeout)
            except FuturesTimeoutError as exc:
                logger.error(f"r2pipe.open() timed out after {timeout:.1f}s")
                self._terminate_radare2_processes()
                raise TimeoutError("r2pipe.open() timed out") from exc

    def _terminate_radare2_processes(self) -> None:
        """Terminate radare2 processes associated with the current filename."""
        target = self.filename
        target_name = Path(self.filename).name
        for proc in psutil.process_iter(["name", "cmdline"]):
            try:
                name = proc.info.get("name") or ""
                cmdline = proc.info.get("cmdline") or []
                if "radare2" not in name:
                    continue
                if any(target in arg for arg in cmdline) or any(
                    target_name in arg for arg in cmdline
                ):
                    proc.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _reopen_safe_mode(self) -> Any:
        """Reopen r2 in safe mode (no analysis) after a timeout."""
        self.close()
        self.r2 = r2pipe.open(self.filename, flags=["-2", "-n"])
        self._cleanup_required = True
        return self.r2

    def _run_cmd_with_timeout(self, command: str, timeout: float) -> bool:
        """Run an r2 command with a timeout, returning True if completed."""
        r2_instance = self.r2
        if r2_instance is None:
            return False
        forced = os.environ.get("R2INSPECT_FORCE_CMD_TIMEOUT", "")
        if forced:
            commands = {item.strip() for item in forced.split(",") if item.strip()}
            if not commands or command in commands:
                logger.warning("Forcing r2 command timeout: %s", command)
                return False
        completed = threading.Event()
        error: dict[str, Exception | None] = {"exc": None}

        def _run() -> None:
            try:
                r2_instance.cmd(command)
            except Exception as exc:
                error["exc"] = exc
            finally:
                completed.set()

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        if not completed.wait(timeout=timeout):
            logger.warning("r2 command timed out: %s", command)
            return False
        if error["exc"] is not None:
            logger.warning("r2 command failed (%s): %s", command, error["exc"])
            return False
        return True

    def _run_basic_info_check(self) -> bool:
        """
        Run a basic info command to verify r2 responsiveness.

        Raises:
            RuntimeError: If r2 cannot properly analyze the file
        """
        if self.r2 is None:
            raise RuntimeError("r2pipe is not initialized")
        if not self._run_cmd_with_timeout("i", self._get_cmd_timeout()):
            return False
        try:
            info_result = self.r2.cmd("i")
            if not info_result or len(info_result.strip()) < MIN_INFO_RESPONSE_LENGTH:
                logger.warning(f"r2 basic info command returned minimal data for {self.filename}")
        except Exception as e:
            logger.error(f"r2 basic info test failed: {e}")
            raise RuntimeError(f"r2 cannot properly analyze this file: {e}")
        return True

    def _perform_initial_analysis(self, file_size_mb: float) -> bool:
        """
        Perform size-aware initial analysis with r2.

        Args:
            file_size_mb: Size of the file in megabytes

        In test mode (R2INSPECT_TEST_MODE=1):
        - Uses more aggressive thresholds to skip analysis earlier
        - Uses shorter timeouts to fail fast
        - Respects R2INSPECT_ANALYSIS_DEPTH to control analysis depth:
          - 0: Skip all analysis
          - 1: Use 'aa' (standard analysis) only
          - 2+: Use 'aaa' (full analysis)
        """
        try:
            if self.r2 is None:
                raise RuntimeError("r2pipe is not initialized")

            # Check if analysis should be skipped entirely (test mode optimization)
            analysis_depth = os.environ.get("R2INSPECT_ANALYSIS_DEPTH", "").strip()
            if analysis_depth == "0":
                logger.debug("Analysis depth set to 0, skipping automatic analysis...")
                return True

            huge_threshold = self._get_huge_file_threshold()
            large_threshold = self._get_large_file_threshold()

            if file_size_mb > huge_threshold:
                logger.debug(
                    f"{'Test mode: ' if self._is_test_mode else ''}Very large file "
                    f"({file_size_mb:.1f}MB > {huge_threshold}MB), skipping automatic analysis..."
                )
                return True

            # In test mode or for large files, use minimal analysis (aa)
            if self._is_test_mode or file_size_mb > large_threshold:
                logger.debug(
                    f"{'Test mode: ' if self._is_test_mode else 'Large file: '}"
                    "Using standard analysis (aa command)..."
                )
                if not self._run_cmd_with_timeout(
                    "aa", self._get_analysis_timeout(full_analysis=False)
                ):
                    return False
                logger.debug("Standard analysis (aa) completed")
                return True

            # Full analysis only for small files in production mode
            logger.debug("Running full analysis (aaa command)...")
            if not self._run_cmd_with_timeout(
                "aaa", self._get_analysis_timeout(full_analysis=True)
            ):
                return False
            logger.debug("Full analysis (aaa) completed")
            return True

        except Exception as e:
            logger.warning(f"Analysis command failed, continuing with basic r2 setup: {e}")
            return True

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
