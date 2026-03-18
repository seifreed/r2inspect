#!/usr/bin/env python3
"""CCBHash calculation from function CFGs."""

import hashlib
from typing import Any

from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..abstractions.hashing_strategy import R2HashingStrategy
from ..adapters.analyzer_runner import run_analyzer_on_file
from ..infrastructure.logging import get_logger
from .ccbhash_support import (
    analyze_functions as build_function_analysis,
    build_canonical_representation as build_cfg_canonical_representation,
    calculate_binary_ccbhash as build_binary_ccbhash,
    calculate_function_ccbhash as build_function_ccbhash,
    extract_functions as collect_functions,
    find_similar_functions as build_similar_function_groups,
)

logger = get_logger(__name__)

NO_FUNCTIONS_FOUND = "No functions found in binary"
NO_FUNCTIONS_ANALYZED = "No functions could be analyzed for CCBHash"


class CCBHashAnalyzer(CommandHelperMixin, R2HashingStrategy):
    """CCBHash calculation from function Control Flow Graphs"""

    def __init__(self, adapter: Any, filepath: str) -> None:
        """
        Initialize CCBHash analyzer.

        Args:
            r2_instance: Active r2pipe instance
            filepath: Path to the binary file being analyzed
        """
        super().__init__(adapter=adapter, filepath=filepath)

    def _check_library_availability(self) -> tuple[bool, str | None]:
        """
        Check if CCBHash analysis is available.

        CCBHash only depends on hashlib and r2pipe, which are always available.

        Returns:
            Tuple of (is_available, error_message)
        """
        if CCBHashAnalyzer.is_available():
            return True, None
        return False, "CCBHash analysis is not available"

    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        """
        Calculate binary-wide CCBHash from all function CFGs.

        Returns:
            Tuple of (hash_value, method_used, error_message)
        """
        try:
            # Extract all functions
            functions = self._extract_functions()
            if not functions:
                return None, None, NO_FUNCTIONS_FOUND

            # Calculate CCBHash for each function
            function_hashes = {}
            for func in functions:
                func_name = func.get("name", f"func_{func.get('addr', 'unknown')}")
                func_offset = func.get("addr")

                if func_offset is None:
                    continue

                ccbhash = self._calculate_function_ccbhash(func_offset, func_name)
                if ccbhash:
                    function_hashes[func_name] = {
                        "ccbhash": ccbhash,
                        "addr": func_offset,
                        "size": func.get("size", 0),
                    }

            if not function_hashes:
                return None, None, NO_FUNCTIONS_ANALYZED

            # Calculate binary-wide CCBHash
            binary_ccbhash = self._calculate_binary_ccbhash(function_hashes)
            if binary_ccbhash:
                return binary_ccbhash, "cfg_analysis", None
            return None, None, "Failed to calculate binary CCBHash"

        except Exception as e:
            logger.error("Error calculating CCBHash: %s", e)
            return None, None, f"CCBHash calculation failed: {str(e)}"

    def _get_hash_type(self) -> str:
        """
        Return the hash type identifier.

        Returns:
            Hash type string
        """
        return "ccbhash"

    def analyze_functions(self) -> dict[str, Any]:
        """
        Perform detailed CCBHash analysis on all functions in the binary.

        This method provides function-level CCBHash analysis in addition
        to the binary-wide hash provided by analyze().

        Returns:
            Dictionary containing detailed CCBHash analysis results
        """
        logger.debug("Starting detailed CCBHash analysis for %s", self.filepath)
        return build_function_analysis(self, logger, NO_FUNCTIONS_FOUND, NO_FUNCTIONS_ANALYZED)

    def _extract_functions(self) -> list[dict[str, Any]]:
        """
        Extract all functions from the binary.

        Returns:
            List of function dictionaries
        """
        return collect_functions(self, logger)

    def _calculate_function_ccbhash(self, func_offset: int, func_name: str) -> str | None:
        """
        Calculate CCBHash for a specific function using its Control Flow Graph.

        Args:
            func_offset: Function offset address
            func_name: Function name for logging

        Returns:
            CCBHash string or None if calculation fails
        """
        return build_function_ccbhash(self, func_offset, func_name, logger)

    @staticmethod
    def _build_canonical_representation(cfg: dict[str, Any], func_offset: int) -> str | None:
        return build_cfg_canonical_representation(cfg, func_offset)

    def _find_similar_functions(
        self, function_hashes: dict[str, dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        Find groups of functions with identical CCBHash (indicating similar structure).

        Args:
            function_hashes: Dictionary of function names to hash data

        Returns:
            List of similar function groups
        """
        return build_similar_function_groups(function_hashes, logger)

    def _calculate_binary_ccbhash(self, function_hashes: dict[str, dict[str, Any]]) -> str | None:
        """
        Calculate a binary-wide CCBHash by combining all function hashes.

        Args:
            function_hashes: Dictionary of function names to hash data

        Returns:
            Binary CCBHash string or None if calculation fails
        """
        return build_binary_ccbhash(function_hashes, logger)

    def get_function_ccbhash(self, func_name: str) -> str | None:
        """
        Get CCBHash for a specific function.

        Args:
            func_name: Name of the function

        Returns:
            CCBHash string or None if not found
        """
        try:
            functions = self._cmd_list("aflj")
            target_func = None

            for func in functions:
                if func.get("name") == func_name:
                    target_func = func
                    break

            if not target_func:
                logger.debug("Function %s not found", func_name)
                return None

            return self._calculate_function_ccbhash(
                target_func["addr"], func_name
            )  # Use 'addr' field

        except Exception as e:
            logger.error("Error getting CCBHash for function %s: %s", func_name, e)
            return None

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> bool | None:
        """
        Compare two CCBHashes for equality.

        CCBHash uses exact string matching since it's a SHA256-based hash.
        Returns True if hashes are identical, False otherwise.

        Args:
            hash1: First CCBHash
            hash2: Second CCBHash

        Returns:
            True if hashes are identical, False if different, None if either is None

        Example:
            >>> hash1 = "abc123..."
            >>> hash2 = "abc123..."
            >>> are_equal = CCBHashAnalyzer.compare_hashes(hash1, hash2)
            >>> if are_equal:
            ...     print("Functions have identical CFG structure")
        """
        if not hash1 or not hash2:
            return None
        return hash1 == hash2

    @staticmethod
    def is_available() -> bool:
        """
        Check if CCBHash analysis is available.

        CCBHash only depends on hashlib and r2pipe, which are always available.

        Returns:
            True (CCBHash is always available)
        """
        return True

    @staticmethod
    def compare_ccbhashes(hash1: str, hash2: str) -> bool:
        """
        Legacy method for comparing CCBHashes (use compare_hashes instead).

        Args:
            hash1: First CCBHash
            hash2: Second CCBHash

        Returns:
            True if hashes are identical, False otherwise
        """
        result = CCBHashAnalyzer.compare_hashes(hash1, hash2)
        return result if result is not None else False

    @staticmethod
    def calculate_ccbhash_from_file(filepath: str) -> dict[str, Any] | None:
        """
        Calculate CCBHash directly from a file path.

        Args:
            filepath: Path to the binary file

        Returns:
            CCBHash analysis results or None if calculation fails
        """
        result = run_analyzer_on_file(CCBHashAnalyzer, filepath)
        if result is None:
            logger.error("Error calculating CCBHash from file")
        return result
