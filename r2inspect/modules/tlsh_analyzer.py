"""
TLSH (Trend Micro Locality Sensitive Hashing) Analyzer Module

This module provides TLSH hashing capabilities for:
- Complete binary
- .text section only
- Individual functions (if size > 512 bytes)

TLSH is particularly useful for malware clustering and similarity detection
as it's resistant to small modifications like compiler changes, padding, etc.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

from typing import Any, cast

# Try to import TLSH library
try:
    import tlsh

    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False

from ..abstractions.hashing_strategy import HashingStrategy
from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmd, safe_cmdj

logger = get_logger(__name__)


class TLSHAnalyzer(HashingStrategy):
    """TLSH (Trend Micro Locality Sensitive Hash) analyzer for sections and functions"""

    def __init__(self, r2, filename: str):
        """
        Initialize TLSH analyzer.

        Args:
            r2: Active r2pipe instance for binary analysis
            filename: Path to the binary file being analyzed
        """
        # Initialize parent with filepath
        super().__init__(filepath=filename, r2_instance=r2)

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
            logger.error(f"Error calculating TLSH hash: {e}")
            return None, None, f"TLSH calculation failed: {str(e)}"

    def _get_hash_type(self) -> str:
        """
        Return the hash type identifier.

        Returns:
            Hash type string
        """
        return "tlsh"

    def analyze_sections(self) -> dict[str, Any]:
        """
        Perform detailed TLSH analysis on binary sections and functions.

        This method provides section-level and function-level TLSH analysis
        in addition to the binary-wide hash provided by analyze().

        Returns:
            Dictionary containing detailed section and function analysis
        """
        if not TLSH_AVAILABLE:
            return {"available": False, "error": "TLSH library not installed"}

        try:
            result: dict[str, Any] = {
                "available": True,
                "binary_tlsh": None,
                "text_section_tlsh": None,
                "section_tlsh": {},
                "function_tlsh": {},
                "stats": {
                    "sections_analyzed": 0,
                    "sections_with_tlsh": 0,
                    "functions_analyzed": 0,
                    "functions_with_tlsh": 0,
                },
            }

            # Get binary-wide TLSH
            result["binary_tlsh"] = self._calculate_binary_tlsh()

            # Get section-wise TLSH
            result["section_tlsh"] = self._calculate_section_tlsh()
            stats = cast(dict[str, int], result["stats"])
            section_hashes = cast(dict[str, str | None], result["section_tlsh"])
            stats["sections_analyzed"] = len(section_hashes)
            stats["sections_with_tlsh"] = sum(1 for v in section_hashes.values() if v)

            # Get text section TLSH specifically
            result["text_section_tlsh"] = section_hashes.get(".text")

            # Get function-wise TLSH (limited to avoid performance issues)
            result["function_tlsh"] = self._calculate_function_tlsh()
            function_hashes = cast(dict[str, str | None], result["function_tlsh"])
            stats["functions_analyzed"] = len(function_hashes)
            stats["functions_with_tlsh"] = sum(1 for v in function_hashes.values() if v)

            return result

        except Exception as e:
            logger.error(f"Error in TLSH analysis: {e}")
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
            with open(self.filepath, "rb") as f:
                data = f.read(max_size)
            if not data or len(data) < self.TLSH_MIN_DATA_SIZE:
                return None
            return cast(str | None, tlsh.hash(data))
        except Exception as e:
            logger.error(f"Error calculating binary TLSH: {e}")
            return None

    def _calculate_section_tlsh(self) -> dict[str, str | None]:
        """Calculate TLSH for each section"""
        section_hashes: dict[str, str | None] = {}

        try:
            sections = cast(list[dict[str, Any]], safe_cmdj(self.r2, "iSj", []))
            if not sections:
                return section_hashes

            for section in sections:
                section_name = section.get("name", "unknown")
                vaddr = section.get("vaddr", 0)
                size = section.get("size", 0)

                if size == 0 or size > 50 * 1024 * 1024:  # Skip empty or very large sections
                    section_hashes[section_name] = None
                    continue

                try:
                    # Read section data
                    read_size = min(size, 1024 * 1024)  # 1MB limit per section
                    hex_data = safe_cmd(self.r2, f"p8 {read_size} @ {vaddr}")
                    section_hashes[section_name] = self._calculate_tlsh_from_hex(hex_data)

                except Exception as e:
                    logger.debug(f"Error calculating TLSH for section {section_name}: {e}")
                    section_hashes[section_name] = None

        except Exception as e:
            logger.error(f"Error in section TLSH calculation: {e}")

        return section_hashes

    def _calculate_function_tlsh(self) -> dict[str, str | None]:
        """Calculate TLSH for functions (limited sample)"""
        function_hashes: dict[str, str | None] = {}

        try:
            # Get functions (core already performed analysis)
            functions = safe_cmdj(self.r2, "aflj")

            if not functions:
                return function_hashes

            # Limit to first 50 functions to avoid performance issues
            functions_to_analyze = functions[:50]

            for func in functions_to_analyze:
                # Skip if function is not a dictionary (malformed data)
                if not isinstance(func, dict):
                    logger.debug(f"Skipping malformed function data: {type(func)} - {func}")
                    continue

                func_name = func.get("name", f"func_{func.get('addr', 'unknown')}")
                func_addr = func.get("addr")
                func_size = func.get("size", 0)

                if not func_addr or func_size == 0 or func_size > 100000:  # Skip large functions
                    function_hashes[func_name] = None
                    continue

                try:
                    # Read function data
                    hex_data = safe_cmd(self.r2, f"p8 {func_size} @ {func_addr}")
                    function_hashes[func_name] = self._calculate_tlsh_from_hex(hex_data)

                except Exception as e:
                    logger.debug(f"Error calculating TLSH for function {func_name}: {e}")
                    function_hashes[func_name] = None

        except Exception as e:
            logger.error(f"Error in function TLSH calculation: {e}")

        return function_hashes

    def compare_tlsh(self, hash1: str, hash2: str) -> int | None:
        """Compare two TLSH hashes and return similarity score"""
        try:
            if not hash1 or not hash2:
                return None

            return cast(int, tlsh.diff(hash1, hash2))

        except Exception as e:
            logger.error(f"Error comparing TLSH hashes: {e}")
            return None

    def find_similar_sections(self, threshold: int = 100) -> list[dict[str, Any]]:
        """Find sections with similar TLSH hashes"""
        try:
            analysis = self.analyze()
            if not analysis.get("available"):
                return []

            section_hashes = analysis.get("section_tlsh", {})
            similar_pairs = []

            # Compare all pairs
            section_names = list(section_hashes.keys())
            for i, name1 in enumerate(section_names):
                hash1 = section_hashes[name1]
                if not hash1:
                    continue

                for name2 in section_names[i + 1 :]:
                    hash2 = section_hashes[name2]
                    if not hash2:
                        continue

                    similarity = self.compare_tlsh(hash1, hash2)
                    if similarity is not None and similarity <= threshold:
                        similar_pairs.append(
                            {
                                "section1": name1,
                                "section2": name2,
                                "similarity_score": similarity,
                                "hash1": hash1,
                                "hash2": hash2,
                            }
                        )

            return sorted(similar_pairs, key=lambda x: x["similarity_score"])

        except Exception as e:
            logger.error(f"Error finding similar sections: {e}")
            return []

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
            logger.warning(f"TLSH comparison failed: {e}")
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
        if score is None:
            return "Unknown"
        elif score == 0:
            return "Identical"
        elif score <= 30:
            return "Very Similar"
        elif score <= 50:
            return "Similar"
        elif score <= 100:
            return "Somewhat Similar"
        elif score <= 200:
            return "Different"
        else:
            return "Very Different"
