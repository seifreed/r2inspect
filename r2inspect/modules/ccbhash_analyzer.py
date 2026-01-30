#!/usr/bin/env python3
"""
CCBHash Analyzer Module

This module calculates CCBHash (Compound Code Block Hash) from function Control Flow Graphs.
CCBHash captures the logical structure of functions and is resistant to minor code changes,
recompilation, and light obfuscation.

Based on research from NICS Lab:
- https://github.com/pblprz/ccbhash
- RECSI 2022: CCBHash - Compound Code Block Hash para Análisis de Malware
- https://recsi2022.unican.es/wp-content/uploads/2022/10/LibroActas-978-84-19024-14-5.pdf

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

import hashlib
from typing import Any

from ..abstractions.hashing_strategy import HashingStrategy
from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmdj

logger = get_logger(__name__)

NO_FUNCTIONS_FOUND = "No functions found in binary"
NO_FUNCTIONS_ANALYZED = "No functions could be analyzed for CCBHash"


class CCBHashAnalyzer(HashingStrategy):
    """CCBHash calculation from function Control Flow Graphs"""

    def __init__(self, r2_instance, filepath: str):
        """
        Initialize CCBHash analyzer.

        Args:
            r2_instance: Active r2pipe instance
            filepath: Path to the binary file being analyzed
        """
        # Initialize parent with filepath
        super().__init__(filepath=filepath, r2_instance=r2_instance)

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
            logger.error(f"Error calculating CCBHash: {e}")
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
        logger.debug(f"Starting detailed CCBHash analysis for {self.filepath}")

        results = {
            "available": False,
            "function_hashes": {},
            "total_functions": 0,
            "analyzed_functions": 0,
            "unique_hashes": 0,
            "similar_functions": [],
            "binary_ccbhash": None,
            "error": None,
        }

        try:
            # Extract all functions
            functions = self._extract_functions()
            if not functions:
                results["error"] = NO_FUNCTIONS_FOUND
                logger.debug(NO_FUNCTIONS_FOUND)
                return results

            results["total_functions"] = len(functions)
            logger.debug(f"Found {len(functions)} functions to analyze")

            # Calculate CCBHash for each function
            function_hashes = {}
            analyzed_count = 0

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
                    analyzed_count += 1

            if not function_hashes:
                results["error"] = NO_FUNCTIONS_ANALYZED
                logger.debug(NO_FUNCTIONS_ANALYZED)
                return results

            # Analyze results
            results["available"] = True
            results["function_hashes"] = function_hashes
            results["analyzed_functions"] = analyzed_count

            # Calculate unique hashes
            unique_hashes = {f["ccbhash"] for f in function_hashes.values()}
            results["unique_hashes"] = len(unique_hashes)

            # Find similar functions (same CCBHash)
            similar_functions = self._find_similar_functions(function_hashes)
            results["similar_functions"] = similar_functions

            # Calculate binary-wide CCBHash
            binary_ccbhash = self._calculate_binary_ccbhash(function_hashes)
            results["binary_ccbhash"] = binary_ccbhash

            logger.debug(
                f"CCBHash analysis completed: {analyzed_count}/{len(functions)} functions analyzed"
            )
            logger.debug(
                f"Found {len(unique_hashes)} unique hashes, {len(similar_functions)} similar function groups"
            )

        except Exception as e:
            logger.error(f"CCBHash analysis failed: {e}")
            results["error"] = str(e)

        return results

    def _extract_functions(self) -> list[dict[str, Any]]:
        """
        Extract all functions from the binary.

        Returns:
            List of function dictionaries
        """
        try:
            # Analysis is performed at core initialization

            # Get function list in JSON format using safe_cmd_list like function_analyzer
            from ..utils.r2_helpers import safe_cmd_list

            functions = safe_cmd_list(self.r2, "aflj")

            if not functions:
                logger.debug("No functions found with 'aflj' command")
                return []

            # Filter out invalid functions - use 'addr' field like function_analyzer
            valid_functions = []
            for func in functions:
                if func.get("addr") is not None and func.get("size", 0) > 0:
                    # Clean HTML entities from function names
                    if "name" in func and func["name"]:
                        func["name"] = func["name"].replace("&nbsp;", " ").replace("&amp;", "&")
                    valid_functions.append(func)

            logger.debug(f"Extracted {len(valid_functions)} valid functions")
            return valid_functions

        except Exception as e:
            logger.error(f"Error extracting functions: {e}")
            return []

    def _calculate_function_ccbhash(self, func_offset: int, func_name: str) -> str | None:
        """
        Calculate CCBHash for a specific function using its Control Flow Graph.

        Args:
            func_offset: Function offset address
            func_name: Function name for logging

        Returns:
            CCBHash string or None if calculation fails
        """
        try:
            # Seek to function
            self.r2.cmd(f"s {func_offset}")

            # Force JSON output format
            self.r2.cmd("e scr.html=false")

            # Get Control Flow Graph in JSON format
            cfg_data = safe_cmdj(self.r2, "agj", [])

            if not cfg_data or len(cfg_data) == 0:
                logger.debug(f"No CFG data found for function {func_name}")
                return None

            # Take the first CFG (should be the current function)
            cfg = cfg_data[0]

            # Extract edges from CFG
            edges = cfg.get("edges", [])

            if not edges:
                # Function might be a single basic block with no edges
                # Use basic blocks instead
                blocks = cfg.get("blocks", [])
                if blocks:
                    # Create a canonical representation based on blocks
                    block_addrs = sorted([block.get("offset", 0) for block in blocks])
                    canonical = "|".join(str(addr) for addr in block_addrs)
                else:
                    # No blocks either, use function address
                    canonical = str(func_offset)
            else:
                # Create canonical edge representation
                edge_strs = []
                for edge in edges:
                    src = edge.get("src")
                    dst = edge.get("dst")
                    if src is not None and dst is not None:
                        edge_strs.append(f"{src}->{dst}")

                # Sort for canonical representation
                edge_strs.sort()
                canonical = "|".join(edge_strs)

            # Calculate SHA256 hash of canonical representation
            ccbhash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

            logger.debug(f"CCBHash calculated for {func_name}: {ccbhash[:16]}...")
            return ccbhash

        except Exception as e:
            logger.debug(f"Error calculating CCBHash for function {func_name}: {e}")
            return None

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
        try:
            # Group functions by hash
            hash_groups: dict[str, list[str]] = {}
            for func_name, func_data in function_hashes.items():
                ccbhash = func_data["ccbhash"]
                if ccbhash not in hash_groups:
                    hash_groups[ccbhash] = []
                # Clean HTML entities from function names
                clean_func_name = func_name.replace("&nbsp;", " ").replace("&amp;", "&")
                hash_groups[ccbhash].append(clean_func_name)

            # Find groups with more than one function (similar functions)
            similar_groups: list[dict[str, Any]] = []
            for ccbhash, func_names in hash_groups.items():
                if len(func_names) > 1:
                    similar_groups.append(
                        {
                            "ccbhash": ccbhash,
                            "functions": func_names,
                            "count": len(func_names),
                        }
                    )

            # Sort by group size (largest first)
            similar_groups.sort(key=lambda x: int(x["count"]), reverse=True)

            return similar_groups

        except Exception as e:
            logger.error(f"Error finding similar functions: {e}")
            return []

    def _calculate_binary_ccbhash(self, function_hashes: dict[str, dict[str, Any]]) -> str | None:
        """
        Calculate a binary-wide CCBHash by combining all function hashes.

        Args:
            function_hashes: Dictionary of function names to hash data

        Returns:
            Binary CCBHash string or None if calculation fails
        """
        try:
            if not function_hashes:
                return None

            # Extract all function hashes and sort them for canonical representation
            all_hashes = sorted([func_data["ccbhash"] for func_data in function_hashes.values()])

            # Combine all hashes
            combined = "|".join(all_hashes)

            # Calculate SHA256 hash of combined representation
            binary_ccbhash = hashlib.sha256(combined.encode("utf-8")).hexdigest()

            logger.debug(f"Binary CCBHash calculated: {binary_ccbhash[:16]}...")
            return binary_ccbhash

        except Exception as e:
            logger.error(f"Error calculating binary CCBHash: {e}")
            return None

    def get_function_ccbhash(self, func_name: str) -> str | None:
        """
        Get CCBHash for a specific function.

        Args:
            func_name: Name of the function

        Returns:
            CCBHash string or None if not found
        """
        try:
            # Find function by name
            from ..utils.r2_helpers import safe_cmd_list

            functions = safe_cmd_list(self.r2, "aflj")
            target_func = None

            for func in functions:
                if func.get("name") == func_name:
                    target_func = func
                    break

            if not target_func:
                logger.debug(f"Function {func_name} not found")
                return None

            return self._calculate_function_ccbhash(
                target_func["addr"], func_name
            )  # Use 'addr' field

        except Exception as e:
            logger.error(f"Error getting CCBHash for function {func_name}: {e}")
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
        try:
            import r2pipe

            with r2pipe.open(filepath, flags=["-2"]) as r2:
                analyzer = CCBHashAnalyzer(r2, filepath)
                return analyzer.analyze()

        except Exception as e:
            logger.error(f"Error calculating CCBHash from file: {e}")
            return None
