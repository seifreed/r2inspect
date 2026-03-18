#!/usr/bin/env python3
"""Impfuzzy hash calculation for PE imports."""

from typing import Any

from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..abstractions.hashing_strategy import R2HashingStrategy
from ..infrastructure.file_type import is_pe_file
from ..infrastructure.logging import get_logger
from ..infrastructure.ssdeep_loader import get_ssdeep
from .impfuzzy_support import (
    analyze_imports as _analyze_imports_impl,
    calculate_impfuzzy_from_file as _calculate_impfuzzy_from_file_impl,
    compare_hashes as _compare_hashes_impl,
    extract_imports as _extract_imports_impl,
    process_imports as _process_imports_impl,
)

logger = get_logger(__name__)

# Try to import impfuzzy library
try:
    import pyimpfuzzy

    IMPFUZZY_AVAILABLE = True
    logger.debug("pyimpfuzzy library available")
except ImportError:  # pragma: no cover
    try:
        import impfuzzy as pyimpfuzzy

        IMPFUZZY_AVAILABLE = True
        logger.debug("impfuzzy library available")
    except ImportError:
        IMPFUZZY_AVAILABLE = False
        logger.debug("impfuzzy library not available")


class ImpfuzzyAnalyzer(CommandHelperMixin, R2HashingStrategy):
    """Impfuzzy hash calculation from PE import table"""

    def __init__(self, adapter: Any, filepath: str) -> None:
        """
        Initialize Impfuzzy analyzer.

        Args:
            r2_instance: Active r2pipe instance
            filepath: Path to the PE file being analyzed
        """
        super().__init__(adapter=adapter, filepath=filepath)

    def _check_library_availability(self) -> tuple[bool, str | None]:
        """
        Check if impfuzzy library is available.

        Returns:
            Tuple of (is_available, error_message)
        """
        if ImpfuzzyAnalyzer.is_available():
            return True, None
        return (
            False,
            "pyimpfuzzy library not available. Install with: pip install pyimpfuzzy",
        )

    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        """
        Calculate impfuzzy hash for the PE file.

        Returns:
            Tuple of (hash_value, method_used, error_message)
        """
        try:
            # Check if file is PE
            if not self._is_pe_file():
                return None, None, "File is not a PE binary"

            # Calculate impfuzzy hash directly from file
            impfuzzy_hash = pyimpfuzzy.get_impfuzzy(str(self.filepath))

            if impfuzzy_hash:
                logger.debug("Impfuzzy hash calculated: %s", impfuzzy_hash)
                return impfuzzy_hash, "python_library", None
            else:
                return (
                    None,
                    None,
                    "No imports found or failed to calculate impfuzzy hash",
                )

        except Exception as e:
            logger.error("Error calculating impfuzzy hash: %s", e)
            return None, None, f"Impfuzzy calculation failed: {str(e)}"

    def _get_hash_type(self) -> str:
        """
        Return the hash type identifier.

        Returns:
            Hash type string
        """
        return "impfuzzy"

    def analyze_imports(self) -> dict[str, Any]:
        """
        Perform detailed impfuzzy analysis on PE file including import statistics.

        This method provides detailed import analysis in addition to the
        impfuzzy hash provided by analyze().

        Returns:
            Dictionary containing detailed impfuzzy analysis results
        """
        logger.debug("Starting detailed impfuzzy analysis for %s", self.filepath)
        return _analyze_imports_impl(
            self,
            impfuzzy_available=IMPFUZZY_AVAILABLE,
            pyimpfuzzy=pyimpfuzzy,
            logger=logger,
        )

    def _is_pe_file(self) -> bool:
        """
        Check if the file is a PE binary.

        Returns:
            True if file is PE, False otherwise
        """
        return is_pe_file(self.filepath, self.adapter, self.r2, logger=logger)

    def _extract_imports(self) -> list[dict[str, Any]]:
        """
        Extract imports from PE file using r2pipe.

        Returns:
            List of import dictionaries or None if extraction fails
        """
        return _extract_imports_impl(self, logger=logger)

    def _process_imports(self, imports_data: list[dict[str, Any]]) -> list[str]:
        """
        Process import data into dll.function format required by impfuzzy.

        Args:
            imports_data: List of import dictionaries from r2pipe

        Returns:
            List of strings in format "dll.function"
        """
        return _process_imports_impl(imports_data, logger=logger)

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> int | None:
        """
        Compare two impfuzzy hashes and return similarity score.

        Impfuzzy uses SSDeep-based comparison, returning a percentage (0-100)
        where higher values indicate greater similarity.

        Args:
            hash1: First impfuzzy hash
            hash2: Second impfuzzy hash

        Returns:
            Similarity score (0-100, higher is more similar) or None if comparison fails

        Example:
            >>> hash1 = "3:abcd..."
            >>> hash2 = "3:abce..."
            >>> similarity = ImpfuzzyAnalyzer.compare_hashes(hash1, hash2)
            >>> if similarity is not None and similarity > 70:
            ...     print("Very similar")
        """
        return _compare_hashes_impl(
            hash1,
            hash2,
            impfuzzy_available=IMPFUZZY_AVAILABLE,
            logger=logger,
            get_ssdeep_fn=get_ssdeep,
        )

    @staticmethod
    def is_available() -> bool:
        """
        Check if impfuzzy library is available.

        Returns:
            True if impfuzzy library can be imported, False otherwise
        """
        return IMPFUZZY_AVAILABLE

    @staticmethod
    def calculate_impfuzzy_from_file(filepath: str) -> str | None:
        """
        Calculate impfuzzy hash directly from a file path.

        Args:
            filepath: Path to the PE file

        Returns:
            Impfuzzy hash string or None if calculation fails
        """
        return _calculate_impfuzzy_from_file_impl(
            filepath,
            impfuzzy_available=IMPFUZZY_AVAILABLE,
            pyimpfuzzy=pyimpfuzzy,
            logger=logger,
        )
