"""
TLSH (Trend Micro Locality Sensitive Hashing) Analyzer Module

This module provides TLSH hashing capabilities for:
- Complete binary
- .text section only
- Individual functions (if size > 512 bytes)

TLSH is particularly useful for malware clustering and similarity detection
as it's resistant to small modifications like compiler changes, padding, etc.
"""

import logging
import hashlib
from typing import Dict, List, Any, Optional

# Try to import TLSH library
try:
    import tlsh

    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False

from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmd, safe_cmdj

logger = get_logger(__name__)


class TLSHAnalyzer:
    """TLSH (Trend Micro Locality Sensitive Hash) analyzer for sections and functions"""

    def __init__(self, r2, config):
        self.r2 = r2
        self.config = config
        self.tlsh_available = self._check_tlsh_availability()

    def _check_tlsh_availability(self) -> bool:
        """Check if TLSH library is available"""
        try:
            import tlsh

            return True
        except ImportError:
            logger.warning(
                "TLSH library not available. Install with: pip install python-tlsh"
            )
            return False

    def analyze(self) -> Dict[str, Any]:
        """Perform TLSH analysis on binary sections"""
        if not self.tlsh_available:
            return {"available": False, "error": "TLSH library not installed"}

        try:
            result = {
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
            result["stats"]["sections_analyzed"] = len(result["section_tlsh"])
            result["stats"]["sections_with_tlsh"] = sum(
                1 for v in result["section_tlsh"].values() if v
            )

            # Get text section TLSH specifically
            result["text_section_tlsh"] = result["section_tlsh"].get(".text")

            # Get function-wise TLSH (limited to avoid performance issues)
            result["function_tlsh"] = self._calculate_function_tlsh()
            result["stats"]["functions_analyzed"] = len(result["function_tlsh"])
            result["stats"]["functions_with_tlsh"] = sum(
                1 for v in result["function_tlsh"].values() if v
            )

            return result

        except Exception as e:
            logger.error(f"Error in TLSH analysis: {e}")
            return {"available": False, "error": str(e)}

    def _calculate_binary_tlsh(self) -> Optional[str]:
        """Calculate TLSH for entire binary"""
        try:
            import tlsh

            # Get file size
            file_info = safe_cmdj(self.r2, "ij")
            if not file_info or "bin" not in file_info:
                return None

            file_size = file_info["bin"].get("size", 0)
            if file_size == 0:
                return None

            # Read binary data (limit to reasonable size)
            max_size = min(file_size, 10 * 1024 * 1024)  # 10MB limit
            hex_data = safe_cmd(self.r2, f"p8 {max_size}")

            if not hex_data or not hex_data.strip():
                return None

            try:
                data = bytes.fromhex(hex_data.strip())
                if len(data) < 50:  # TLSH requires minimum data size
                    return None

                return tlsh.hash(data)

            except ValueError:
                return None

        except Exception as e:
            logger.error(f"Error calculating binary TLSH: {e}")
            return None

    def _calculate_section_tlsh(self) -> Dict[str, Optional[str]]:
        """Calculate TLSH for each section"""
        section_hashes = {}

        try:
            import tlsh

            sections = safe_cmdj(self.r2, "iSj")
            if not sections:
                return section_hashes

            for section in sections:
                # Skip if section is not a dictionary (malformed data)
                if not isinstance(section, dict):
                    logger.debug(
                        f"Skipping malformed section data: {type(section)} - {section}"
                    )
                    continue

                section_name = section.get("name", "unknown")
                vaddr = section.get("vaddr", 0)
                size = section.get("size", 0)

                if (
                    size == 0 or size > 50 * 1024 * 1024
                ):  # Skip empty or very large sections
                    section_hashes[section_name] = None
                    continue

                try:
                    # Read section data
                    read_size = min(size, 1024 * 1024)  # 1MB limit per section
                    hex_data = safe_cmd(self.r2, f"p8 {read_size} @ {vaddr}")

                    if not hex_data or not hex_data.strip():
                        section_hashes[section_name] = None
                        continue

                    data = bytes.fromhex(hex_data.strip())
                    if len(data) < 50:  # TLSH minimum
                        section_hashes[section_name] = None
                        continue

                    section_hashes[section_name] = tlsh.hash(data)

                except Exception as e:
                    logger.debug(
                        f"Error calculating TLSH for section {section_name}: {e}"
                    )
                    section_hashes[section_name] = None

        except Exception as e:
            logger.error(f"Error in section TLSH calculation: {e}")

        return section_hashes

    def _calculate_function_tlsh(self) -> Dict[str, Optional[str]]:
        """Calculate TLSH for functions (limited sample)"""
        function_hashes = {}

        try:
            import tlsh

            # Get functions
            self.r2.cmd("aaa")  # Ensure analysis is complete
            functions = safe_cmdj(self.r2, "aflj")

            if not functions:
                return function_hashes

            # Limit to first 50 functions to avoid performance issues
            functions_to_analyze = functions[:50]

            for func in functions_to_analyze:
                # Skip if function is not a dictionary (malformed data)
                if not isinstance(func, dict):
                    logger.debug(
                        f"Skipping malformed function data: {type(func)} - {func}"
                    )
                    continue

                func_name = func.get("name", f"func_{func.get('addr', 'unknown')}")
                func_addr = func.get("addr")
                func_size = func.get("size", 0)

                if (
                    not func_addr or func_size == 0 or func_size > 100000
                ):  # Skip large functions
                    function_hashes[func_name] = None
                    continue

                try:
                    # Read function data
                    hex_data = safe_cmd(self.r2, f"p8 {func_size} @ {func_addr}")

                    if not hex_data or not hex_data.strip():
                        function_hashes[func_name] = None
                        continue

                    data = bytes.fromhex(hex_data.strip())
                    if len(data) < 50:  # TLSH minimum
                        function_hashes[func_name] = None
                        continue

                    function_hashes[func_name] = tlsh.hash(data)

                except Exception as e:
                    logger.debug(
                        f"Error calculating TLSH for function {func_name}: {e}"
                    )
                    function_hashes[func_name] = None

        except Exception as e:
            logger.error(f"Error in function TLSH calculation: {e}")

        return function_hashes

    def compare_tlsh(self, hash1: str, hash2: str) -> Optional[int]:
        """Compare two TLSH hashes and return similarity score"""
        try:
            import tlsh

            if not hash1 or not hash2:
                return None

            return tlsh.diff(hash1, hash2)

        except Exception as e:
            logger.error(f"Error comparing TLSH hashes: {e}")
            return None

    def find_similar_sections(self, threshold: int = 100) -> List[Dict[str, Any]]:
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
    def compare_hashes(hash1: str, hash2: str) -> Optional[int]:
        """
        Compare two TLSH hashes and return similarity score.

        Args:
            hash1: First TLSH hash
            hash2: Second TLSH hash

        Returns:
            Similarity score (lower is more similar) or None if comparison fails
        """
        if not TLSH_AVAILABLE:
            return None

        if not hash1 or not hash2:
            return None

        try:
            score = tlsh.diff(hash1, hash2)
            return score
        except Exception as e:
            logger.warning(f"TLSH comparison failed: {e}")
            return None

    @staticmethod
    def is_available() -> bool:
        """
        Check if TLSH is available.

        Returns:
            True if TLSH is available, False otherwise
        """
        return TLSH_AVAILABLE

    @staticmethod
    def get_similarity_level(score: int) -> str:
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
