"""
SSDeep (Fuzzy Hashing) Analyzer Module

This module provides fuzzy hashing capabilities using ssdeep for approximate
file similarity detection. It supports both the Python ssdeep library and
system binary as fallback.
"""

import os
import subprocess
from typing import Any, Dict, Optional

# Try to import ssdeep library, fallback to system binary if not available
try:
    import ssdeep

    SSDEEP_LIBRARY_AVAILABLE = True
except ImportError:
    SSDEEP_LIBRARY_AVAILABLE = False

from ..utils.logger import get_logger

logger = get_logger(__name__)


class SSDeepAnalyzer:
    """SSDeep fuzzy hashing analyzer for file similarity detection."""

    def __init__(self, filepath: str):
        """
        Initialize SSDeep analyzer.

        Args:
            filepath: Path to the file to analyze
        """
        self.filepath = filepath
        self.ssdeep_hash = None
        self.method_used = None

    def analyze(self) -> Dict[str, Any]:
        """
        Perform SSDeep analysis on the file.

        Returns:
            Dictionary containing SSDeep analysis results
        """
        logger.debug(f"Starting SSDeep analysis for {self.filepath}")

        results = {
            "ssdeep_hash": None,
            "method_used": None,
            "available": False,
            "error": None,
        }

        # Try Python library first
        if SSDEEP_LIBRARY_AVAILABLE:
            try:
                results = self._analyze_with_library()
                logger.debug(
                    f"SSDeep hash calculated using Python library: {results['ssdeep_hash']}"
                )
                return results
            except Exception as e:
                logger.warning(f"Python ssdeep library failed: {e}")
                results["error"] = f"Library error: {str(e)}"

        # Fallback to system binary
        try:
            results = self._analyze_with_binary()
            if results["ssdeep_hash"]:
                logger.debug(
                    f"SSDeep hash calculated using system binary: {results['ssdeep_hash']}"
                )
                return results
        except Exception as e:
            logger.warning(f"System ssdeep binary failed: {e}")
            results["error"] = f"Binary error: {str(e)}"

        logger.error("SSDeep analysis failed - no method available")
        return results

    def _analyze_with_library(self) -> Dict[str, Any]:
        """
        Calculate SSDeep hash using Python library.

        Returns:
            Dictionary with analysis results
        """
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"File not found: {self.filepath}")

        # Calculate ssdeep hash - read file content manually to avoid file handle issues
        try:
            with open(self.filepath, "rb") as f:
                file_content = f.read()
            ssdeep_hash = ssdeep.hash(file_content)
        except OSError as e:
            # Fall back to hash_from_file if direct read fails
            try:
                ssdeep_hash = ssdeep.hash_from_file(self.filepath)
            except Exception:
                raise e

        return {
            "ssdeep_hash": ssdeep_hash,
            "method_used": "python_library",
            "available": True,
            "error": None,
        }

    def _analyze_with_binary(self) -> Dict[str, Any]:
        """
        Calculate SSDeep hash using system binary.

        Returns:
            Dictionary with analysis results
        """
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"File not found: {self.filepath}")

        # Check if ssdeep binary is available
        if not self._is_ssdeep_binary_available():
            raise RuntimeError("ssdeep binary not found in PATH")

        # Run ssdeep command
        try:
            result = subprocess.run(
                ["ssdeep", "-s", self.filepath],
                capture_output=True,
                text=True,
                timeout=30,
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
                        break
            else:
                raise RuntimeError("Could not parse ssdeep output")

            return {
                "ssdeep_hash": ssdeep_hash,
                "method_used": "system_binary",
                "available": True,
                "error": None,
            }

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
        try:
            result = subprocess.run(["ssdeep", "-V"], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> Optional[int]:
        """
        Compare two SSDeep hashes and return similarity score.

        Args:
            hash1: First SSDeep hash
            hash2: Second SSDeep hash

        Returns:
            Similarity score (0-100) or None if comparison fails
        """
        if not hash1 or not hash2:
            return None

        # Try Python library first
        if SSDEEP_LIBRARY_AVAILABLE:
            try:
                return ssdeep.compare(hash1, hash2)
            except Exception as e:
                logger.warning(f"SSDeep comparison failed with library: {e}")

        # Fallback to system binary
        try:
            # Create temporary files for comparison
            import tempfile

            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f1:
                f1.write(f"{hash1},file1\n")
                f1.flush()

                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f2:
                    f2.write(f"{hash2},file2\n")
                    f2.flush()

                    # Run ssdeep comparison
                    result = subprocess.run(
                        ["ssdeep", "-k", f1.name, f2.name],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )

                    # Clean up temp files
                    os.unlink(f1.name)
                    os.unlink(f2.name)

                    if result.returncode == 0:
                        # Parse output for similarity score
                        for line in result.stdout.split("\n"):
                            if "matches" in line and "(" in line and ")" in line:
                                # Extract percentage from output like "file1 matches file2 (85)"
                                start = line.rfind("(")
                                end = line.rfind(")")
                                if start != -1 and end != -1:
                                    return int(line[start + 1 : end])

        except Exception as e:
            logger.warning(f"SSDeep comparison failed with binary: {e}")

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
            result = subprocess.run(["ssdeep", "-V"], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
