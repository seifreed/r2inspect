#!/usr/bin/env python3
"""
SimHash Analyzer Module

This module implements SimHash-based binary similarity analysis using both strings and opcodes.
SimHash is a locality-sensitive hash function that maps high-dimensional features to a fixed-size
hash while preserving similarity relationships. It's particularly useful for:

- Detecting similar binaries with small variations
- Clustering functions or binaries by structural similarity
- Efficient similarity matching at scale
- Malware family identification and variant detection

The implementation extracts features from:
1. Strings (function context and embedded data)
2. Instruction mnemonics (structural patterns)
3. Function-level patterns (per-function hashing)
4. Binary-wide signatures (global similarity)

Based on Charikar's SimHash algorithm for near-duplicate detection.
Reference: https://en.wikipedia.org/wiki/SimHash

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

from collections import Counter
from typing import Any, cast

from ..abstractions.hashing_strategy import HashingStrategy
from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmd_list, safe_cmdj

logger = get_logger(__name__)

NO_FEATURES_ERROR = "No features could be extracted for SimHash"
# Try to import simhash, fall back to error handling
try:
    from simhash import Simhash

    SIMHASH_AVAILABLE = True
except ImportError:
    logger.warning("simhash not available. Install with: pip install simhash")
    SIMHASH_AVAILABLE = False
    Simhash = None


class SimHashAnalyzer(HashingStrategy):
    """SimHash-based binary similarity analysis"""

    def __init__(self, r2_instance, filepath: str):
        """
        Initialize SimHash analyzer.

        Args:
            r2_instance: Active r2pipe instance
            filepath: Path to the binary file being analyzed
        """
        # Initialize parent with filepath
        super().__init__(filepath=filepath, r2_instance=r2_instance)
        self.min_string_length = 4  # Minimum string length to consider
        self.max_instructions_per_function = 500  # Limit instructions per function

    def _check_library_availability(self) -> tuple[bool, str | None]:
        """
        Check if simhash library is available.

        Returns:
            Tuple of (is_available, error_message)
        """
        if SimHashAnalyzer.is_available():
            return True, None
        return False, "simhash library not available. Install with: pip install simhash"

    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        """
        Calculate combined SimHash for the binary from strings and opcodes.

        Returns:
            Tuple of (hash_value, method_used, error_message)
        """
        try:
            # Extract features
            strings_features = self._extract_string_features()
            opcodes_features = self._extract_opcodes_features()

            if not strings_features and not opcodes_features:
                return None, None, NO_FEATURES_ERROR

            # Combined SimHash (strings + opcodes)
            combined_features = strings_features + opcodes_features
            if combined_features:
                combined_simhash = Simhash(combined_features)
                hash_hex = hex(combined_simhash.value)
                logger.debug(f"SimHash calculated: {hash_hex}")
                return hash_hex, "feature_extraction", None

            return None, None, "Failed to calculate SimHash from features"

        except Exception as e:
            logger.error(f"Error calculating SimHash: {e}")
            return None, None, f"SimHash calculation failed: {str(e)}"

    def _get_hash_type(self) -> str:
        """
        Return the hash type identifier.

        Returns:
            Hash type string
        """
        return "simhash"

    def analyze_detailed(self) -> dict[str, Any]:
        """
        Perform detailed SimHash analysis on the binary.

        This method provides separate string-based, opcode-based, and combined
        SimHash analysis in addition to the combined hash provided by analyze().

        Returns:
            Dictionary containing detailed SimHash analysis results
        """
        if not SIMHASH_AVAILABLE:
            return {
                "available": False,
                "error": "simhash library not installed",
                "library_available": False,
            }

        logger.debug(f"Starting detailed SimHash analysis for {self.filepath}")

        results: dict[str, Any] = {
            "available": False,
            "library_available": True,
            "binary_simhash": None,
            "strings_simhash": None,
            "opcodes_simhash": None,
            "combined_simhash": None,
            "function_simhashes": {},
            "total_functions": 0,
            "analyzed_functions": 0,
            "feature_stats": {},
            "similarity_groups": [],
            "error": None,
        }

        try:
            # Extract features
            strings_features = self._extract_string_features()
            opcodes_features = self._extract_opcodes_features()
            function_features = self._extract_function_features()

            if not strings_features and not opcodes_features:
                results["error"] = NO_FEATURES_ERROR
                logger.debug(NO_FEATURES_ERROR)
                return results

            # Calculate different SimHash variants
            results["available"] = True

            # Strings-only SimHash
            if strings_features:
                strings_simhash = Simhash(strings_features)
                results["strings_simhash"] = {
                    "hash": strings_simhash.value,
                    "hex": hex(strings_simhash.value),
                    "binary": bin(strings_simhash.value),
                    "feature_count": len(strings_features),
                }

            # Opcodes-only SimHash
            if opcodes_features:
                opcodes_simhash = Simhash(opcodes_features)
                results["opcodes_simhash"] = {
                    "hash": opcodes_simhash.value,
                    "hex": hex(opcodes_simhash.value),
                    "binary": bin(opcodes_simhash.value),
                    "feature_count": len(opcodes_features),
                }

            # Combined SimHash (strings + opcodes)
            combined_features = strings_features + opcodes_features
            if combined_features:
                combined_simhash = Simhash(combined_features)
                results["combined_simhash"] = {
                    "hash": combined_simhash.value,
                    "hex": hex(combined_simhash.value),
                    "binary": bin(combined_simhash.value),
                    "feature_count": len(combined_features),
                }
                results["binary_simhash"] = results[
                    "combined_simhash"
                ]  # Alias for binary-wide hash

            # Function-level SimHashes
            if function_features:
                results["function_simhashes"] = function_features
                results["total_functions"] = len(
                    [f for f in function_features.values() if f.get("simhash")]
                )
                results["analyzed_functions"] = len(
                    [f for f in function_features.values() if f.get("simhash")]
                )

                # Find similar functions
                similar_groups = self._find_similar_functions(function_features)
                results["similarity_groups"] = similar_groups

            # Feature statistics
            feature_stats: dict[str, Any] = {
                "total_strings": len(strings_features),
                "total_opcodes": len(opcodes_features),
                "total_features": len(combined_features),
                "unique_strings": len(set(strings_features)) if strings_features else 0,
                "unique_opcodes": len(set(opcodes_features)) if opcodes_features else 0,
            }

            # Add frequency analysis
            if combined_features:
                feature_counter = Counter(combined_features)
                feature_stats["most_common_features"] = feature_counter.most_common(10)
                feature_stats["feature_diversity"] = len(set(combined_features)) / len(
                    combined_features
                )

            results["feature_stats"] = feature_stats

            logger.debug(f"SimHash analysis completed: {len(combined_features)} total features")
            logger.debug(
                f"Binary SimHash: {hex(combined_simhash.value) if combined_features else 'N/A'}"
            )

        except Exception as e:
            logger.error(f"SimHash analysis failed: {e}")
            results["error"] = str(e)

        return results

    def _extract_string_features(self) -> list[str]:
        """
        Extract string features from the binary.

        Returns:
            List of string features
        """
        string_features: list[str] = []

        try:
            # Extract strings using r2pipe
            strings_data = safe_cmd_list(self.r2, "izj")

            if isinstance(strings_data, list):
                self._collect_string_features(strings_data, string_features)

            # Also extract strings from data sections
            data_strings = self._extract_data_section_strings()
            string_features.extend(data_strings)

            logger.debug(f"Extracted {len(string_features)} string features")
            return string_features

        except Exception as e:
            logger.debug(f"Error extracting string features: {e}")
            return []

    def _collect_string_features(self, strings_data: list[Any], string_features: list[str]) -> None:
        for string_entry in strings_data:
            if not isinstance(string_entry, dict) or "string" not in string_entry:
                continue
            string_value = string_entry["string"]
            if len(string_value) < self.min_string_length:
                continue
            if not self._is_useful_string(string_value):
                continue
            self._add_string_feature_set(string_features, string_value)

    def _add_string_feature_set(self, string_features: list[str], string_value: str) -> None:
        string_features.append(f"STR:{string_value}")
        length_category = self._get_length_category(len(string_value))
        string_features.append(f"STRLEN:{length_category}")
        string_type = self._classify_string_type(string_value)
        if string_type:
            string_features.append(f"STRTYPE:{string_type}")

    def _extract_opcodes_features(self) -> list[str]:
        """
        Extract opcode/instruction features from the binary.

        Returns:
            List of opcode features
        """
        opcode_features: list[str] = []

        try:
            # Analysis is performed at core initialization

            # Extract all functions
            functions = safe_cmd_list(self.r2, "aflj")

            if not functions:
                logger.debug("No functions found for opcode extraction, trying alternative methods")
                # Try alternative function discovery
                functions = safe_cmd_list(self.r2, "afl")
                if not functions:
                    return []

            # Process each function
            for func in functions:
                # Handle both 'offset' and 'addr' fields
                func_addr = func.get("offset") or func.get("addr")
                if func_addr is None:
                    continue

                func_name = func.get("name", f"func_{func_addr}")

                # Seek to function and extract instructions
                self.r2.cmd(f"s {func_addr}")

                # Get function instructions
                func_opcodes = self._extract_function_opcodes(func_name)
                if func_opcodes:
                    opcode_features.extend(func_opcodes)
                    logger.debug(f"Extracted {len(func_opcodes)} opcodes from {func_name}")

                # Limit total opcodes to avoid memory issues
                if len(opcode_features) > 10000:
                    logger.debug("Opcode feature limit reached, truncating")
                    break

            logger.debug(
                f"Extracted {len(opcode_features)} opcode features from {len(functions)} functions"
            )
            return opcode_features

        except Exception as e:
            logger.debug(f"Error extracting opcode features: {e}")
            return []

    def _extract_function_features(self) -> dict[str, dict[str, Any]]:
        """
        Extract per-function SimHash features.

        Returns:
            Dictionary of function features with SimHash values
        """
        function_features = {}

        try:
            # Extract all functions
            functions = safe_cmd_list(self.r2, "aflj")

            if not functions:
                return {}

            for func in functions:
                if not isinstance(func, dict) or "offset" not in func:
                    continue

                func_addr = func["offset"]
                func_name = func.get("name", f"func_{func_addr}")
                func_size = func.get("size", 0)

                # Extract features for this specific function
                self.r2.cmd(f"s {func_addr}")

                func_opcodes = self._extract_function_opcodes(func_name)
                if not func_opcodes:
                    continue

                # Create SimHash for this function
                try:
                    func_simhash = Simhash(func_opcodes)

                    function_features[func_name] = {
                        "addr": func_addr,
                        "size": func_size,
                        "simhash": func_simhash.value,
                        "simhash_hex": hex(func_simhash.value),
                        "feature_count": len(func_opcodes),
                        "unique_opcodes": len(set(func_opcodes)),
                    }

                except Exception as e:
                    logger.debug(f"Error creating SimHash for function {func_name}: {e}")
                    continue

            logger.debug(f"Extracted SimHash features for {len(function_features)} functions")
            return function_features

        except Exception as e:
            logger.debug(f"Error extracting function features: {e}")
            return {}

    def _extract_function_opcodes(self, func_name: str) -> list[str]:
        """
        Extract opcodes from a specific function.

        Args:
            func_name: Function name for logging

        Returns:
            List of opcode features
        """
        opcodes: list[str] = []

        try:
            disasm = safe_cmdj(self.r2, "pdfj", {})
            if disasm and "ops" in disasm:
                return self._extract_opcodes_from_ops(disasm["ops"])

            disasm_list = safe_cmd_list(self.r2, f"pdj {self.max_instructions_per_function}")
            if isinstance(disasm_list, list):
                return self._extract_opcodes_from_ops(disasm_list)

        except Exception as e:
            logger.debug(f"Error extracting opcodes from function {func_name}: {e}")

        return opcodes

    def _extract_opcodes_from_ops(self, ops: list[Any]) -> list[str]:
        opcodes: list[str] = []
        for i, op in enumerate(ops):
            if i >= self.max_instructions_per_function:
                break
            if not isinstance(op, dict) or "mnemonic" not in op:
                continue
            mnemonic = op["mnemonic"].strip().lower()
            if not mnemonic:
                continue
            opcodes.append(f"OP:{mnemonic}")
            op_type = self._classify_opcode_type(mnemonic)
            if op_type:
                opcodes.append(f"OPTYPE:{op_type}")
            prev_mnemonic = self._get_prev_mnemonic(ops, i)
            if prev_mnemonic:
                opcodes.append(f"BIGRAM:{prev_mnemonic}→{mnemonic}")
        return opcodes

    def _get_prev_mnemonic(self, ops: list[Any], index: int) -> str | None:
        if index <= 0 or index >= len(ops):
            return None
        prev_op = ops[index - 1]
        if isinstance(prev_op, dict) and "mnemonic" in prev_op:
            return prev_op["mnemonic"].strip().lower()
        return None

    def _extract_data_section_strings(self) -> list[str]:
        """Extract strings from data sections."""
        data_strings: list[str] = []

        try:
            sections = safe_cmd_list(self.r2, "iSj")
            if isinstance(sections, list):
                for section in sections:
                    self._append_data_section_string(section, data_strings)

        except Exception as e:
            logger.debug(f"Error extracting data section strings: {e}")

        return data_strings

    def _append_data_section_string(self, section: Any, data_strings: list[str]) -> None:
        if not isinstance(section, dict) or not section.get("name", "").startswith(".data"):
            return
        section_addr = section.get("vaddr", 0)
        section_size = section.get("size", 0)
        if not (section_addr and section_size):
            return
        self.r2.cmd(f"s {section_addr}")
        section_strings = self.r2.cmd(f"ps {min(section_size, 1024)}")
        if section_strings and len(section_strings.strip()) >= self.min_string_length:
            data_strings.append(f"DATASTR:{section_strings.strip()}")

    def _is_useful_string(self, string_value: str) -> bool:
        """Check if a string is useful for SimHash analysis."""
        # Filter out very common or useless strings
        useless_patterns = [
            r"^\s*$",  # Empty or whitespace only
            r"^[0-9]+$",  # Numbers only
            r"^[a-f0-9]{8,}$",  # Hex strings
        ]

        import re

        for pattern in useless_patterns:
            if re.match(pattern, string_value, re.IGNORECASE):
                return False

        # Check for printable characters
        printable_ratio = sum(1 for c in string_value if c.isprintable()) / len(string_value)
        return printable_ratio > 0.8

    def _get_length_category(self, length: int) -> str:
        """Categorize string length."""
        if length < 8:
            return "short"
        elif length < 32:
            return "medium"
        elif length < 128:
            return "long"
        else:
            return "very_long"

    def _classify_string_type(self, string_value: str) -> str | None:
        """Classify string type for feature extraction."""
        import re

        # URL pattern
        if re.match(r"https?://", string_value, re.IGNORECASE):
            return "url"

        # File path pattern
        if re.match(r"[a-z]:\\|/", string_value, re.IGNORECASE):
            return "path"

        # Registry key pattern
        if re.match(r"HKEY_|SOFTWARE\\|SYSTEM\\", string_value, re.IGNORECASE):
            return "registry"

        # API or function name pattern
        if re.match(r"^[A-Z][a-zA-Z0-9_]*[A-Z]", string_value):
            return "api"

        # Error message pattern
        if any(
            word in string_value.lower() for word in ["error", "failed", "exception", "invalid"]
        ):
            return "error"

        return None

    def _classify_opcode_type(self, mnemonic: str) -> str | None:
        """Classify opcode type for feature extraction."""
        # Control flow instructions
        if mnemonic in [
            "jmp",
            "je",
            "jne",
            "jz",
            "jnz",
            "jg",
            "jl",
            "jge",
            "jle",
            "call",
            "ret",
        ]:
            return "control"

        # Data movement
        if mnemonic in ["mov", "lea", "push", "pop", "xchg"]:
            return "data"

        # Arithmetic
        if mnemonic in ["add", "sub", "mul", "div", "inc", "dec", "neg"]:
            return "arithmetic"

        # Logical
        if mnemonic in ["and", "or", "xor", "not", "shl", "shr", "rol", "ror"]:
            return "logical"

        # Comparison
        if mnemonic in ["cmp", "test"]:
            return "compare"

        # String operations
        if mnemonic.startswith("str") or mnemonic.startswith("rep"):
            return "string"

        return "other"

    def _find_similar_functions(
        self, function_features: dict[str, dict[str, Any]], max_distance: int = 10
    ) -> list[dict[str, Any]]:
        """
        Find groups of similar functions based on SimHash distance.

        Args:
            function_features: Dictionary of function features
            max_distance: Maximum Hamming distance for similarity

        Returns:
            List of similar function groups
        """
        try:
            if not SIMHASH_AVAILABLE:
                return []

            similar_groups: list[dict[str, Any]] = []
            processed_functions = set()

            func_names = list(function_features.keys())

            for i, func1_name in enumerate(func_names):
                if func1_name in processed_functions:
                    continue

                func1_data = function_features[func1_name]
                func1_simhash = Simhash(func1_data["simhash"])

                similar_funcs = [func1_name]
                processed_functions.add(func1_name)

                # Compare with remaining functions
                for j, func2_name in enumerate(func_names[i + 1 :], i + 1):
                    if func2_name in processed_functions:
                        continue

                    func2_data = function_features[func2_name]
                    func2_simhash = Simhash(func2_data["simhash"])

                    # Calculate Hamming distance
                    distance = func1_simhash.distance(func2_simhash)

                    if distance <= max_distance:
                        similar_funcs.append(func2_name)
                        processed_functions.add(func2_name)

                # Add group if it has more than one function
                if len(similar_funcs) > 1:
                    similar_groups.append(
                        {
                            "functions": similar_funcs,
                            "count": len(similar_funcs),
                            "representative_hash": hex(func1_data["simhash"]),
                            "max_distance": max_distance,
                        }
                    )

            # Sort by group size
            similar_groups.sort(key=lambda x: int(x.get("count", 0)), reverse=True)

            return similar_groups

        except Exception as e:
            logger.error(f"Error finding similar functions: {e}")
            return []

    def calculate_similarity(
        self, other_simhash_value: int, hash_type: str = "combined"
    ) -> dict[str, Any]:
        """
        Calculate similarity between this binary and another SimHash value.

        Args:
            other_simhash_value: SimHash value to compare against
            hash_type: Type of hash to use ('combined', 'strings', 'opcodes')

        Returns:
            Dictionary with similarity metrics
        """
        if not SIMHASH_AVAILABLE:
            return {"error": "simhash library not available"}

        try:
            # Get current analysis results
            results = self.analyze()

            if not results.get("available"):
                return {"error": "SimHash analysis not available"}

            # Get the appropriate hash
            current_hash = None
            if hash_type == "combined" and results.get("combined_simhash"):
                current_hash = results["combined_simhash"]["hash"]
            elif hash_type == "strings" and results.get("strings_simhash"):
                current_hash = results["strings_simhash"]["hash"]
            elif hash_type == "opcodes" and results.get("opcodes_simhash"):
                current_hash = results["opcodes_simhash"]["hash"]

            if current_hash is None:
                return {"error": f"No {hash_type} SimHash available"}

            # Calculate distance
            current_simhash = Simhash(current_hash)
            other_simhash = Simhash(other_simhash_value)

            distance = current_simhash.distance(other_simhash)

            # Interpret similarity
            if distance == 0:
                similarity_level = "identical"
            elif distance <= 5:
                similarity_level = "very_similar"
            elif distance <= 15:
                similarity_level = "similar"
            elif distance <= 25:
                similarity_level = "somewhat_similar"
            else:
                similarity_level = "different"

            return {
                "distance": distance,
                "similarity_level": similarity_level,
                "current_hash": hex(current_hash),
                "other_hash": hex(other_simhash_value),
                "hash_type": hash_type,
            }

        except Exception as e:
            logger.error(f"Error calculating similarity: {e}")
            return {"error": str(e)}

    @staticmethod
    def compare_hashes(hash1: str | int, hash2: str | int) -> int | None:
        """
        Compare two SimHash values and return Hamming distance.

        SimHash comparison uses Hamming distance where lower values indicate
        greater similarity. A distance of 0 means identical hashes.

        Args:
            hash1: First SimHash value (hex string like '0x1234abcd')
            hash2: Second SimHash value (hex string like '0x1234abcd')

        Returns:
            Hamming distance (0-64 for 64-bit hash, lower is more similar) or None if comparison fails

        Example:
            >>> hash1 = "0x1a2b3c4d"
            >>> hash2 = "0x1a2b3c5d"
            >>> distance = SimHashAnalyzer.compare_hashes(hash1, hash2)
            >>> if distance is not None and distance <= 5:
            ...     print("Very similar")
        """
        if not SIMHASH_AVAILABLE:
            return None

        if not hash1 or not hash2:
            return None

        try:
            # Convert hex strings to integers
            hash1_int = int(hash1, 16) if isinstance(hash1, str) else hash1

            hash2_int = int(hash2, 16) if isinstance(hash2, str) else hash2

            # Create Simhash objects and calculate distance
            simhash1 = Simhash(hash1_int)
            simhash2 = Simhash(hash2_int)

            return cast(int, simhash1.distance(simhash2))

        except Exception as e:
            logger.warning(f"SimHash comparison failed: {e}")
            return None

    @staticmethod
    def is_available() -> bool:
        """
        Check if SimHash library is available.

        Returns:
            True if simhash library can be imported, False otherwise
        """
        return SIMHASH_AVAILABLE

    @staticmethod
    def calculate_simhash_from_file(filepath: str) -> dict[str, Any] | None:
        """
        Calculate SimHash directly from a file path.

        Args:
            filepath: Path to the binary file

        Returns:
            SimHash analysis results or None if calculation fails
        """
        try:
            import r2pipe

            with r2pipe.open(filepath, flags=["-2"]) as r2:
                analyzer = SimHashAnalyzer(r2, filepath)
                return analyzer.analyze()

        except Exception as e:
            logger.error(f"Error calculating SimHash from file: {e}")
            return None
