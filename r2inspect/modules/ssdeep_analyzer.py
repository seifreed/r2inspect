"""
SSDeep (Fuzzy Hashing) Analyzer Module

This module provides fuzzy hashing capabilities using ssdeep for approximate
file similarity detection. It supports both the Python ssdeep library and
system binary as fallback.

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

import os
import shutil
import subprocess  # nosec B404 - required for calling ssdeep binary safely
import tempfile
from pathlib import Path
from typing import Any, cast

# Try to import ssdeep library, fallback to system binary if not available
try:
    import ssdeep

    SSDEEP_LIBRARY_AVAILABLE = True
except ImportError:
    SSDEEP_LIBRARY_AVAILABLE = False

from ..abstractions.hashing_strategy import HashingStrategy
from ..security.validators import FileValidator
from ..utils.logger import get_logger

logger = get_logger(__name__)


class SSDeepAnalyzer(HashingStrategy):
    """SSDeep fuzzy hashing analyzer for file similarity detection."""

    def __init__(
        self,
        filepath: str,
        r2_instance=None,
        max_file_size: int = 100 * 1024 * 1024,
        min_file_size: int = 1,
    ):
        super().__init__(
            filepath=filepath,
            r2_instance=r2_instance,
            max_file_size=max_file_size,
            min_file_size=min_file_size,
        )
        self.ssdeep_hash: str | None = None
        self.method_used: str | None = None

    def analyze(self):
        """Override to provide backward-compatible key names (ssdeep_hash)."""
        base = super().analyze()
        self.ssdeep_hash = base.get("hash_value")
        self.method_used = base.get("method_used")
        # Map generic keys to legacy-friendly ones
        if base.get("hash_value"):
            base["ssdeep_hash"] = base["hash_value"]
        else:
            base.setdefault("ssdeep_hash", None)
        return base

    def _analyze_with_library(self) -> dict[str, Any]:
        """Run analysis using the Python ssdeep library only."""
        if not SSDEEP_LIBRARY_AVAILABLE:
            raise ImportError("ssdeep library not available")

        try:
            with open(self.filepath, "rb") as f:
                file_content = f.read()
            ssdeep_hash = ssdeep.hash(file_content)
            self.ssdeep_hash = ssdeep_hash
            self.method_used = "python_library"
            return {
                "available": True,
                "method_used": "python_library",
                "ssdeep_hash": ssdeep_hash,
                "error": None,
            }
        except Exception as e:
            raise RuntimeError(f"ssdeep library analysis failed: {e}")

    def _analyze_with_binary(self) -> dict[str, Any]:
        """Run analysis using the ssdeep system binary only."""
        ssdeep_hash, method = self._calculate_with_binary()
        self.ssdeep_hash = ssdeep_hash
        self.method_used = method
        return {
            "available": True,
            "method_used": method,
            "ssdeep_hash": ssdeep_hash,
            "error": None,
        }

    def _check_library_availability(self) -> tuple[bool, str | None]:
        """
        Check if SSDeep is available (either library or binary).

        Returns:
            Tuple of (is_available, error_message)
        """
        if SSDeepAnalyzer.is_available():
            return True, None

        return (
            False,
            "SSDeep not available. Install with: pip install ssdeep or install system binary",
        )

    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        """
        Calculate SSDeep hash for the file.

        Returns:
            Tuple of (hash_value, method_used, error_message)
        """
        # Try Python library first
        if SSDEEP_LIBRARY_AVAILABLE:
            try:
                with open(self.filepath, "rb") as f:
                    file_content = f.read()
                ssdeep_hash = ssdeep.hash(file_content)
                logger.debug(f"SSDeep hash calculated using Python library: {ssdeep_hash}")
                return ssdeep_hash, "python_library", None
            except OSError:
                # Fall back to hash_from_file if direct read fails
                try:
                    ssdeep_hash = ssdeep.hash_from_file(str(self.filepath))
                    logger.debug(f"SSDeep hash calculated using hash_from_file: {ssdeep_hash}")
                    return ssdeep_hash, "python_library", None
                except Exception as lib_error:
                    logger.warning(f"Python ssdeep library failed: {lib_error}")
                    # Continue to try binary method
            except Exception as e:
                logger.warning(f"Python ssdeep library failed: {e}")
                # Continue to try binary method

        # Fallback to system binary
        try:
            ssdeep_hash, method = self._calculate_with_binary()
            if ssdeep_hash:
                logger.debug(f"SSDeep hash calculated using system binary: {ssdeep_hash}")
                return ssdeep_hash, method, None
            return None, None, "SSDeep binary calculation returned no hash"
        except Exception as e:
            logger.error(f"System ssdeep binary failed: {e}")
            return None, None, f"Binary error: {str(e)}"

    def _calculate_with_binary(self) -> tuple[str | None, str]:
        """
        Calculate SSDeep hash using system binary.

        Security: Prevents command injection (CWE-78) by:
        1. Validating file path through FileValidator
        2. Using subprocess with shell=False
        3. Passing arguments as list (not string)
        4. Implementing timeout to prevent DoS

        Returns:
            Tuple of (hash_value, method_used)

        Raises:
            RuntimeError: If binary is not available or calculation fails
        """
        # Check if ssdeep binary is available
        ssdeep_path = self._resolve_ssdeep_binary()
        if not ssdeep_path:
            raise RuntimeError("ssdeep binary not found in PATH")

        # SECURITY FIX: Validate and sanitize filepath to prevent command injection (CWE-78)
        try:
            validator = FileValidator()
            validated_path = validator.validate_path(str(self.filepath), check_exists=True)
            safe_filepath = validator.sanitize_for_subprocess(validated_path)
        except ValueError as e:
            raise RuntimeError(f"File path validation failed: {e}")

        # Run ssdeep command with validated path
        # SECURITY: shell=False prevents shell injection, timeout prevents DoS
        try:
            result = subprocess.run(
                [ssdeep_path, "-s", safe_filepath],
                capture_output=True,
                text=True,
                timeout=30,
                shell=False,  # CRITICAL: Never use shell=True with user input
                check=False,
                # nosec B603 - arguments are fixed and path is validated
            )

            if result.returncode != 0:
                raise RuntimeError(f"ssdeep command failed: {result.stderr}")

            # Parse output - format is: "hash,filename"
            output_lines = result.stdout.strip().split("\n")
            for line in output_lines:
                if line and not line.startswith("ssdeep"):
                    # Extract hash (everything before the last comma)
                    parts = line.rsplit(",", 1)
                    if len(parts) == 2:
                        ssdeep_hash = parts[0]
                        return ssdeep_hash, "system_binary"

            raise RuntimeError("Could not parse ssdeep output")

        except subprocess.TimeoutExpired:
            raise RuntimeError("ssdeep command timed out")
        except subprocess.SubprocessError as e:
            raise RuntimeError(f"ssdeep subprocess error: {e}")

    def _is_ssdeep_binary_available(self) -> bool:
        """
        Check if ssdeep binary is available in PATH.

        Returns:
            True if ssdeep binary is available, False otherwise
        """
        return self._resolve_ssdeep_binary() is not None

    @staticmethod
    def _resolve_ssdeep_binary() -> str | None:
        """Resolve ssdeep binary to an absolute path to avoid partial-path execution."""
        ssdeep_path = shutil.which("ssdeep")
        return ssdeep_path

    def _get_hash_type(self) -> str:
        """
        Return the hash type identifier.

        Returns:
            Hash type string
        """
        return "ssdeep"

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> int | None:
        """
        Compare two SSDeep hashes and return similarity score.

        Security: Prevents insecure temporary file handling (CWE-377, CWE-379) by:
        1. Using TemporaryDirectory for automatic cleanup
        2. Setting restrictive permissions (0o600) on temp files
        3. Ensuring cleanup even on exceptions
        4. Using try-finally for guaranteed cleanup

        Args:
            hash1: First SSDeep hash
            hash2: Second SSDeep hash

        Returns:
            Similarity score (0-100) or None if comparison fails
        """
        if not hash1 or not hash2:
            return None

        library_score = SSDeepAnalyzer._compare_with_library(hash1, hash2)
        if library_score is not None:
            return library_score

        return SSDeepAnalyzer._compare_with_binary(hash1, hash2)

    @staticmethod
    def _compare_with_library(hash1: str, hash2: str) -> int | None:
        if not SSDEEP_LIBRARY_AVAILABLE:
            return None
        try:
            return cast(int, ssdeep.compare(hash1, hash2))
        except Exception as e:
            logger.warning(f"SSDeep comparison failed with library: {e}")
            return None

    @staticmethod
    def _compare_with_binary(hash1: str, hash2: str) -> int | None:
        temp_dir = None
        try:
            temp_dir = tempfile.TemporaryDirectory(prefix="r2inspect_ssdeep_")
            temp_dir_path = Path(temp_dir.name)

            temp_file1 = temp_dir_path / "hash1.txt"
            temp_file2 = temp_dir_path / "hash2.txt"

            SSDeepAnalyzer._write_temp_hash_file(temp_file1, f"{hash1},file1\n")
            SSDeepAnalyzer._write_temp_hash_file(temp_file2, f"{hash2},file2\n")

            ssdeep_path = SSDeepAnalyzer._resolve_ssdeep_binary()
            if not ssdeep_path:
                return None
            result = subprocess.run(
                [ssdeep_path, "-k", str(temp_file1), str(temp_file2)],
                capture_output=True,
                text=True,
                timeout=10,
                shell=False,
                check=False,
                # nosec B603 - arguments are fixed and inputs are controlled
            )

            if result.returncode == 0:
                return SSDeepAnalyzer._parse_ssdeep_output(result.stdout)

        except Exception as e:
            logger.warning(f"SSDeep comparison failed with binary: {e}")
        finally:
            if temp_dir is not None:
                try:
                    temp_dir.cleanup()
                except Exception as e:
                    logger.warning(f"Failed to cleanup temporary directory: {e}")

        return None

    @staticmethod
    def _write_temp_hash_file(path: Path, content: str) -> None:
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            mode=0o600,
        )
        try:
            os.write(fd, content.encode())
        finally:
            os.close(fd)

    @staticmethod
    def _parse_ssdeep_output(output: str) -> int | None:
        for line in output.split("\n"):
            if "matches" in line and "(" in line and ")" in line:
                start = line.rfind("(")
                end = line.rfind(")")
                if start != -1 and end != -1:
                    return int(line[start + 1 : end])
        return None

    @staticmethod
    def is_available() -> bool:
        """
        Check if SSDeep is available (either library or binary).

        Returns:
            True if SSDeep is available, False otherwise
        """
        if SSDEEP_LIBRARY_AVAILABLE:
            return True

        # Check system binary
        try:
            ssdeep_path = SSDeepAnalyzer._resolve_ssdeep_binary()
            if not ssdeep_path:
                return False
            result = subprocess.run(
                [ssdeep_path, "-V"],
                capture_output=True,
                text=True,
                timeout=5,
                shell=False,
                check=False,
                # nosec B603 - arguments are fixed and path is validated
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
