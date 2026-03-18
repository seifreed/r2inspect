"""TLSH hashing for binaries, sections, and functions."""

from typing import Any, cast

# Try to import TLSH library
try:
    import tlsh

    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False

from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..abstractions.hashing_strategy import R2HashingStrategy
from ..adapters.file_system import default_file_system
from ..infrastructure.logging import get_logger
from .tlsh_support import (
    build_detailed_analysis,
    calculate_function_tlsh,
    calculate_section_tlsh,
    find_similar_sections as build_similar_sections,
    similarity_level,
)

logger = get_logger(__name__)


class TLSHAnalyzer(CommandHelperMixin, R2HashingStrategy):
    """TLSH (Trend Micro Locality Sensitive Hash) analyzer for sections and functions"""

    def __init__(self, adapter: Any, filename: str) -> None:
        """
        Initialize TLSH analyzer.

        Args:
            r2: Active r2pipe instance for binary analysis
            filename: Path to the binary file being analyzed
        """
        super().__init__(adapter=adapter, filepath=filename)

    def _check_library_availability(self) -> tuple[bool, str | None]:
        """
        Check if TLSH library is available.

        Returns:
            Tuple of (is_available, error_message)
        """
        if TLSHAnalyzer.is_available():
            return True, None
        return (
            False,
            "TLSH library not available. Install with: pip install python-tlsh",
        )

    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        """
        Calculate TLSH hash for the entire binary.

        Returns:
            Tuple of (hash_value, method_used, error_message)
        """
        try:
            hash_value = self._calculate_binary_tlsh()
            if hash_value:
                return hash_value, "python_library", None
            return (
                None,
                None,
                "TLSH calculation returned no hash (file may be too small)",
            )
        except Exception as e:
            logger.error("Error calculating TLSH hash: %s", e)
            return None, None, f"TLSH calculation failed: {str(e)}"

    def _get_hash_type(self) -> str:
        """
        Return the hash type identifier.

        Returns:
            Hash type string
        """
        return "tlsh"

    def analyze(self) -> dict[str, Any]:
        """Run TLSH analysis and include a binary_tlsh field for compatibility."""
        result = super().analyze()
        if "binary_tlsh" not in result:
            result["binary_tlsh"] = result.get("hash_value")
        return result

    def analyze_sections(self) -> dict[str, Any]:
        """
        Perform detailed TLSH analysis on binary sections and functions.

        This method provides section-level and function-level TLSH analysis
        in addition to the binary-wide hash provided by analyze().

        Returns:
            Dictionary containing detailed section and function analysis
        """
        try:
            return build_detailed_analysis(self, TLSH_AVAILABLE)
        except Exception as e:
            logger.error("Error in TLSH analysis: %s", e)
            return {"available": False, "error": str(e)}

    # Minimum data size required for TLSH calculation
    TLSH_MIN_DATA_SIZE = 50

    def _calculate_tlsh_from_hex(self, hex_data: str | None) -> str | None:
        """
        Calculate TLSH hash from hex-encoded data.

        This is a helper method used by both section and function TLSH calculations
        to avoid code duplication.

        Args:
            hex_data: Hex-encoded string of binary data

        Returns:
            TLSH hash string or None if calculation fails
        """
        if not hex_data or not hex_data.strip():
            return None

        try:
            data = bytes.fromhex(hex_data.strip())
            if len(data) < self.TLSH_MIN_DATA_SIZE:
                return None
            return cast(str | None, tlsh.hash(data))
        except Exception:
            return None

    def _calculate_binary_tlsh(self) -> str | None:
        """Calculate TLSH for entire binary (read directly from file for speed)."""
        try:
            # Read directly from filesystem to avoid r2 hex conversion overhead
            max_size = 10 * 1024 * 1024  # 10MB cap
            data = default_file_system.read_bytes(self.filepath, size=max_size)
            if not data or len(data) < self.TLSH_MIN_DATA_SIZE:
                return None
            return cast(str | None, tlsh.hash(data))
        except Exception as e:
            logger.error("Error calculating binary TLSH: %s", e)
            return None

    def _calculate_section_tlsh(self) -> dict[str, str | None]:
        return calculate_section_tlsh(self, logger)

    def _calculate_function_tlsh(self) -> dict[str, str | None]:
        return calculate_function_tlsh(self, logger)

    def _get_sections(self) -> list[Any]:
        return cast(list[Any], self._get_via_adapter("get_sections"))

    def _get_functions(self) -> list[Any]:
        return cast(list[Any], self._get_via_adapter("get_functions"))

    def _read_bytes_hex(self, vaddr: int, size: int) -> str | None:
        if self.adapter is not None and hasattr(self.adapter, "read_bytes"):
            try:
                data = self.adapter.read_bytes(vaddr, size)
                return data.hex() if data else None
            except Exception:
                return None
        return None

    def compare_tlsh(self, hash1: str, hash2: str) -> int | None:
        """Compare two TLSH hashes and return similarity score"""
        try:
            if not hash1 or not hash2:
                return None

            return cast(int, tlsh.diff(hash1, hash2))

        except Exception as e:
            logger.error("Error comparing TLSH hashes: %s", e)
            return None

    def find_similar_sections(self, threshold: int = 100) -> list[dict[str, Any]]:
        """Find sections with similar TLSH hashes"""
        return build_similar_sections(self, threshold, logger)

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> int | None:
        """
        Compare two TLSH hashes and return distance score.

        The TLSH distance metric returns lower values for more similar hashes.
        A distance of 0 indicates identical hashes.

        Args:
            hash1: First TLSH hash
            hash2: Second TLSH hash

        Returns:
            Distance score (lower is more similar, 0-1000+) or None if comparison fails

        Example:
            >>> hash1 = "T1234..."
            >>> hash2 = "T1235..."
            >>> distance = TLSHAnalyzer.compare_hashes(hash1, hash2)
            >>> if distance is not None and distance < 50:
            ...     print("Very similar")
        """
        if not TLSH_AVAILABLE:
            return None

        if not hash1 or not hash2:
            return None

        try:
            score = cast(int, tlsh.diff(hash1, hash2))
            return score
        except Exception as e:
            logger.warning("TLSH comparison failed: %s", e)
            return None

    @staticmethod
    def is_available() -> bool:
        """
        Check if TLSH library is available.

        Returns:
            True if TLSH library can be imported, False otherwise
        """
        return TLSH_AVAILABLE

    @staticmethod
    def get_similarity_level(score: int | None) -> str:
        """
        Get human-readable similarity level based on TLSH score.

        Args:
            score: TLSH difference score

        Returns:
            Similarity level description
        """
        return similarity_level(score)
