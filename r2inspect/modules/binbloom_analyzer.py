#!/usr/bin/env python3
# mypy: ignore-errors
"""
Binbloom Analyzer Module

This module implements Binbloom-style function fingerprinting using Bloom filters.
Bloom filters are space-efficient probabilistic data structures that test whether
an element is a member of a set, with possible false positives but no false negatives.

For binary analysis, this creates compact signatures of functions based on their
instruction mnemonics, useful for:
- Fast function similarity detection
- Compact function fingerprinting
- Probabilistic matching with controlled false positive rates
- Efficient clustering of similar functions

Based on Burton Howard Bloom's 1970 paper on space-efficient probabilistic data structures.
Reference: https://en.wikipedia.org/wiki/Bloom_filter

Security note:
This module has been hardened against deserialization vulnerabilities (CWE-502).
All Bloom filter serialization uses JSON format instead of pickle to prevent
Remote Code Execution (RCE) attacks. The deserialize_bloom() function implements
defense-in-depth with:
- JSON-only deserialization (no arbitrary object instantiation)
- Explicit type validation and sanitization
- Parameter range checking to prevent resource exhaustion
- Version checking for format compatibility

This follows OWASP guidelines for secure deserialization and eliminates the entire
class of pickle-based RCE vulnerabilities (CVSS 9.8 Critical).
"""

import base64
import hashlib
import json
from collections import defaultdict
from typing import Any

from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmd_list, safe_cmdj

logger = get_logger(__name__)

# Try to import pybloom_live, fall back to error handling
try:
    from pybloom_live import BloomFilter

    BLOOM_AVAILABLE = True
except ImportError:
    logger.warning("pybloom-live not available. Install with: pip install pybloom-live")
    BLOOM_AVAILABLE = False
    BloomFilter = None


class BinbloomAnalyzer:
    """Binbloom-style function analysis using Bloom filters"""

    def __init__(self, r2_instance, filepath: str):
        """
        Initialize Binbloom analyzer.

        Args:
            r2_instance: Active r2pipe instance
            filepath: Path to the binary file being analyzed
        """
        self.r2 = r2_instance
        self.filepath = filepath
        self.default_capacity = 256  # Default Bloom filter capacity
        self.default_error_rate = 0.001  # 0.1% false positive rate

    def analyze(
        self, capacity: int | None = None, error_rate: float | None = None
    ) -> dict[str, Any]:
        """
        Perform Binbloom analysis on all functions in the binary.

        Args:
            capacity: Bloom filter capacity (default: 256)
            error_rate: False positive rate (default: 0.001)

        Returns:
            Dictionary containing Binbloom analysis results
        """
        if not BLOOM_AVAILABLE:
            return {
                "available": False,
                "error": "pybloom-live library not installed",
                "library_available": False,
            }

        if capacity is None:
            capacity = self.default_capacity
        if error_rate is None:
            error_rate = self.default_error_rate

        logger.debug(f"Starting Binbloom analysis for {self.filepath}")

        results = {
            "available": False,
            "library_available": True,
            "function_blooms": {},
            "function_signatures": {},
            "total_functions": 0,
            "analyzed_functions": 0,
            "capacity": capacity,
            "error_rate": error_rate,
            "binary_bloom": None,
            "binary_signature": None,
            "similar_functions": [],
            "unique_signatures": 0,
            "bloom_stats": {},
            "error": None,
        }

        try:
            # Extract all functions
            functions = self._extract_functions()
            if not functions:
                results["error"] = "No functions found in binary"
                logger.debug("No functions found in binary")
                return results

            results["total_functions"] = len(functions)
            logger.debug(f"Found {len(functions)} functions to analyze")

            function_blooms, function_signatures, all_instructions, analyzed_count = (
                self._collect_function_blooms(functions, capacity, error_rate)
            )

            if not function_blooms:
                results["error"] = "No functions could be analyzed for Binbloom"
                logger.debug("No functions could be analyzed for Binbloom")
                return results

            # Analyze results
            results["available"] = True
            results["function_blooms"] = self._serialize_blooms(function_blooms)
            results["function_signatures"] = function_signatures
            results["analyzed_functions"] = analyzed_count

            # Calculate unique signatures
            signatures = self._collect_unique_signatures(function_signatures)
            results["unique_signatures"] = len(signatures)

            # Find similar functions (same signature)
            similar_functions = self._find_similar_functions(function_signatures)
            results["similar_functions"] = similar_functions

            # Create binary-wide Bloom filter
            self._add_binary_bloom(results, all_instructions, capacity, error_rate)

            # Calculate Bloom filter statistics
            bloom_stats = self._calculate_bloom_stats(function_blooms, capacity, error_rate)
            results["bloom_stats"] = bloom_stats

            logger.debug(
                f"Binbloom analysis completed: {analyzed_count}/{len(functions)} functions analyzed"
            )
            logger.debug(
                f"Found {len(signatures)} unique signatures, {len(similar_functions)} similar function groups"
            )

        except Exception as e:
            logger.error(f"Binbloom analysis failed: {e}")
            results["error"] = str(e)

        return results

    def _collect_function_blooms(
        self, functions: list[dict[str, Any]], capacity: int, error_rate: float
    ) -> tuple[dict[str, BloomFilter], dict[str, dict[str, Any]], set[str], int]:
        function_blooms: dict[str, BloomFilter] = {}
        function_signatures: dict[str, dict[str, Any]] = {}
        all_instructions: set[str] = set()
        analyzed_count = 0

        for func in functions:
            func_name = func.get("name", f"func_{func.get('addr', 'unknown')}")
            func_name = func_name.replace("&nbsp;", " ").replace("&amp;", "&")
            func_addr = func.get("addr")

            if func_addr is None:
                continue

            bloom_result = self._create_function_bloom(func_addr, func_name, capacity, error_rate)
            if not bloom_result:
                continue

            bloom_filter, instructions, signature = bloom_result
            function_blooms[func_name] = bloom_filter
            function_signatures[func_name] = {
                "signature": signature,
                "instruction_count": len(instructions),
                "unique_instructions": len(set(instructions)),
                "addr": func_addr,
                "size": func.get("size", 0),
            }
            all_instructions.update(instructions)
            analyzed_count += 1

        return function_blooms, function_signatures, all_instructions, analyzed_count

    def _collect_unique_signatures(self, function_signatures: dict[str, dict[str, Any]]) -> set:
        return {sig["signature"] for sig in function_signatures.values()}

    def _add_binary_bloom(
        self,
        results: dict[str, Any],
        all_instructions: set[str],
        capacity: int,
        error_rate: float,
    ) -> None:
        if not all_instructions:
            return
        binary_bloom = self._create_binary_bloom(all_instructions, capacity * 2, error_rate)
        if not binary_bloom:
            return
        binary_signature = self._bloom_to_signature(sorted(all_instructions))
        results["binary_bloom"] = self._serialize_bloom(binary_bloom)
        results["binary_signature"] = binary_signature

    def _extract_functions(self) -> list[dict[str, Any]]:
        """
        Extract all functions from the binary.

        Returns:
            List of function dictionaries
        """
        try:
            # Ensure analysis is complete
            self.r2.cmd("aaa")

            # Get function list
            functions = safe_cmd_list(self.r2, "aflj")

            if not functions:
                logger.debug("No functions found with 'aflj' command")
                return []

            # Filter out invalid functions
            valid_functions = []
            for func in functions:
                if func.get("addr") is not None and func.get("size", 0) > 0:
                    valid_functions.append(func)

            logger.debug(f"Extracted {len(valid_functions)} valid functions")
            return valid_functions

        except Exception as e:
            logger.error(f"Error extracting functions: {e}")
            return []

    def _create_function_bloom(
        self, func_addr: int, func_name: str, capacity: int, error_rate: float
    ) -> tuple[BloomFilter, list[str | None, str]]:
        """
        Create a Bloom filter for a specific function.

        Args:
            func_addr: Function address
            func_name: Function name for logging
            capacity: Bloom filter capacity
            error_rate: False positive rate

        Returns:
            Tuple of (BloomFilter, instructions list, signature) or None if failed
        """
        try:
            # Seek to function
            self.r2.cmd(f"s {func_addr}")

            # Extract instruction mnemonics
            instructions = self._extract_instruction_mnemonics(func_name)
            if not instructions:
                logger.debug(f"No instructions found for function {func_name}")
                return None

            bloom_filter = self._build_bloom_filter(instructions, capacity, error_rate)

            # Create signature from Bloom filter
            signature = self._bloom_to_signature(instructions)

            logger.debug(
                f"Created Bloom filter for {func_name}: {len(instructions)} instructions, signature: {signature[:16]}..."
            )
            return bloom_filter, instructions, signature

        except Exception as e:
            logger.debug(f"Error creating Bloom filter for function {func_name}: {e}")
            return None

    def _build_bloom_filter(
        self, instructions: list[str], capacity: int, error_rate: float
    ) -> BloomFilter:
        bloom_filter = BloomFilter(capacity=capacity, error_rate=error_rate)
        for instruction in instructions:
            bloom_filter.add(instruction)
        self._add_instruction_patterns(bloom_filter, instructions)
        return bloom_filter

    def _add_instruction_patterns(self, bloom_filter: BloomFilter, instructions: list[str]) -> None:
        for i in range(len(instructions) - 1):
            bigram = f"{instructions[i]}→{instructions[i + 1]}"
            bloom_filter.add(bigram)

        from collections import Counter

        freq_counter = Counter(instructions)
        for instr, count in freq_counter.items():
            if count > 1:
                bloom_filter.add(f"{instr}*{count}")

    def _extract_instruction_mnemonics(self, func_name: str) -> list[str]:
        """
        Extract instruction mnemonics from current function.

        Args:
            func_name: Function name for logging

        Returns:
            List of instruction mnemonics
        """
        try:
            instructions = self._extract_mnemonics_from_pdfj(func_name)
            if instructions:
                return instructions

            instructions = self._extract_mnemonics_from_pdj(func_name)
            if instructions:
                return instructions

            instructions = self._extract_mnemonics_from_text(func_name)
            if instructions:
                return instructions

        except Exception as e:
            logger.debug(f"Error extracting mnemonics from {func_name}: {e}")

        return []

    def _extract_mnemonics_from_pdfj(self, func_name: str) -> list[str]:
        disasm = safe_cmdj(self.r2, "pdfj", {})
        if not disasm or "ops" not in disasm:
            return []
        mnemonics = self._collect_mnemonics_from_ops(disasm["ops"])
        if mnemonics:
            logger.debug(f"Extracted {len(mnemonics)} mnemonics from {func_name} using pdfj")
        return mnemonics

    def _extract_mnemonics_from_pdj(self, func_name: str) -> list[str]:
        disasm_list = safe_cmd_list(self.r2, "pdj 200")
        if not isinstance(disasm_list, list):
            return []
        mnemonics = self._collect_mnemonics_from_ops(disasm_list)
        if mnemonics:
            logger.debug(f"Extracted {len(mnemonics)} mnemonics from {func_name} using pdj")
        return mnemonics

    def _extract_mnemonics_from_text(self, func_name: str) -> list[str]:
        instructions_text = self.r2.cmd("pi 100")
        if not instructions_text or not instructions_text.strip():
            return []
        mnemonics: list[str] = []
        for line in instructions_text.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            mnemonic = line.split()[0]
            clean_mnemonic = self._normalize_mnemonic(mnemonic)
            if clean_mnemonic:
                mnemonics.append(clean_mnemonic)
        if mnemonics:
            logger.debug(f"Extracted {len(mnemonics)} mnemonics from {func_name} using pi")
        return mnemonics

    def _collect_mnemonics_from_ops(self, ops: list[Any]) -> list[str]:
        mnemonics: list[str] = []
        for op in ops:
            if not isinstance(op, dict) or "mnemonic" not in op:
                continue
            clean_mnemonic = self._normalize_mnemonic(op.get("mnemonic"))
            if clean_mnemonic:
                mnemonics.append(clean_mnemonic)
        return mnemonics

    def _normalize_mnemonic(self, mnemonic: str | None) -> str | None:
        if not mnemonic:
            return None
        clean_mnemonic = mnemonic.strip().lower()
        return clean_mnemonic or None

    def _bloom_to_signature(self, instructions: list[str]) -> str:
        """
        Create a deterministic signature from a Bloom filter.

        Args:
            bloom_filter: The Bloom filter
            instructions: Original instructions for deterministic hashing

        Returns:
            SHA256 signature string
        """
        try:
            # Create a more detailed signature that includes:
            # 1. Unique instructions (sorted)
            # 2. Instruction frequency patterns
            # 3. Instruction sequence patterns (bigrams)

            signature_components = self._build_signature_components(instructions)

            combined = "||".join(signature_components)

            # Create SHA256 hash
            signature = hashlib.sha256(combined.encode("utf-8")).hexdigest()
            return signature

        except Exception as e:
            logger.error(f"Error creating signature from Bloom filter: {e}")
            return ""

    def _build_signature_components(self, instructions: list[str]) -> list[str]:
        unique_instructions = sorted(set(instructions))
        freq_patterns = self._build_frequency_patterns(instructions, unique_instructions)
        unique_bigrams = self._build_unique_bigrams(instructions)
        return [
            "UNIQ:" + "|".join(unique_instructions),
            "FREQ:" + "|".join(freq_patterns),
            "BIGR:" + "|".join(unique_bigrams[:20]),
        ]

    def _build_frequency_patterns(
        self, instructions: list[str], unique_instructions: list[str]
    ) -> list[str]:
        from collections import Counter

        freq_counter = Counter(instructions)
        return [f"{instr}:{freq_counter[instr]}" for instr in unique_instructions]

    def _build_unique_bigrams(self, instructions: list[str]) -> list[str]:
        bigrams: list[str] = []
        for i in range(len(instructions) - 1):
            bigram = f"{instructions[i]}→{instructions[i + 1]}"
            bigrams.append(bigram)
        return sorted(set(bigrams))

    def _create_binary_bloom(
        self, all_instructions: set[str], capacity: int, error_rate: float
    ) -> BloomFilter | None:
        """
        Create a binary-wide Bloom filter from all instructions.

        Args:
            all_instructions: Set of all instructions in the binary
            capacity: Bloom filter capacity
            error_rate: False positive rate

        Returns:
            BloomFilter or None if creation fails
        """
        try:
            bloom_filter = BloomFilter(capacity=capacity, error_rate=error_rate)

            for instruction in all_instructions:
                bloom_filter.add(instruction)

            return bloom_filter

        except Exception as e:
            logger.error(f"Error creating binary Bloom filter: {e}")
            return None

    def _serialize_blooms(self, function_blooms: dict[str, BloomFilter]) -> dict[str, str]:
        """
        Serialize Bloom filters to base64-encoded JSON strings for storage/transport.

        SECURITY: Uses JSON serialization instead of pickle to prevent deserialization
        vulnerabilities (CWE-502). The bitarray is converted to a list of booleans,
        which is safe to deserialize.

        Args:
            function_blooms: Dictionary of function names to Bloom filters

        Returns:
            Dictionary of function names to base64-encoded JSON Bloom filters
        """
        serialized = {}

        try:
            for func_name, bloom_filter in function_blooms.items():
                # Serialize Bloom filter to JSON (secure method)
                serialized[func_name] = self._serialize_bloom(bloom_filter)

        except Exception as e:
            logger.error(f"Error serializing Bloom filters: {e}")

        return serialized

    def _serialize_bloom(self, bloom_filter: BloomFilter) -> str:
        """
        Serialize a single Bloom filter to base64-encoded JSON string.

        SECURITY: Uses JSON serialization to avoid pickle deserialization vulnerabilities
        (CWE-502: Deserialization of Untrusted Data). The bitarray is converted to a
        list of booleans which is safe to deserialize without code execution risks.

        Args:
            bloom_filter: The Bloom filter to serialize

        Returns:
            Base64-encoded JSON string containing Bloom filter parameters
        """
        try:
            # Create JSON-serializable dictionary with all necessary parameters
            data = {
                "version": 1,  # Format version for future compatibility
                "error_rate": bloom_filter.error_rate,
                "capacity": bloom_filter.capacity,
                "count": bloom_filter.count,
                "bitarray": bloom_filter.bitarray.tolist(),  # Convert to list of booleans (safe)
            }

            # Serialize to JSON then base64 encode for compact storage
            json_str = json.dumps(data, separators=(",", ":"))  # Compact format
            return base64.b64encode(json_str.encode("utf-8")).decode("utf-8")
        except Exception as e:
            logger.error(f"Error serializing Bloom filter: {e}")
            return ""

    def _find_similar_functions(
        self, function_signatures: dict[str, dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        Find groups of functions with identical signatures.

        Args:
            function_signatures: Dictionary of function signatures

        Returns:
            List of similar function groups
        """
        try:
            signature_groups = self._group_functions_by_signature(function_signatures)
            similar_groups = self._build_similar_groups(signature_groups)
            similar_groups.sort(key=lambda x: x["count"], reverse=True)
            return similar_groups

        except Exception as e:
            logger.error(f"Error finding similar functions: {e}")
            return []

    def _group_functions_by_signature(
        self, function_signatures: dict[str, dict[str, Any]]
    ) -> dict[str, list[str]]:
        signature_groups: dict[str, list[str]] = defaultdict(list)
        for func_name, func_data in function_signatures.items():
            signature = func_data["signature"]
            clean_func_name = func_name.replace("&nbsp;", " ").replace("&amp;", "&")
            signature_groups[signature].append(clean_func_name)
        return signature_groups

    def _build_similar_groups(self, signature_groups: dict[str, list[str]]) -> list[dict[str, Any]]:
        similar_groups: list[dict[str, Any]] = []
        for signature, func_names in signature_groups.items():
            if len(func_names) > 1:
                similar_groups.append(
                    {
                        "signature": signature[:16] + "..." if len(signature) > 16 else signature,
                        "functions": func_names,
                        "count": len(func_names),
                    }
                )
        return similar_groups

    def _calculate_bloom_stats(
        self, function_blooms: dict[str, BloomFilter], capacity: int, error_rate: float
    ) -> dict[str, Any]:
        """
        Calculate statistics about the Bloom filters.

        Args:
            function_blooms: Dictionary of Bloom filters
            capacity: Bloom filter capacity
            error_rate: False positive rate

        Returns:
            Dictionary of statistics
        """
        try:
            if not function_blooms:
                return {}

            total_bits_set, total_capacity = self._accumulate_bloom_bits(function_blooms)

            stats = {
                "total_filters": len(function_blooms),
                "configured_capacity": capacity,
                "configured_error_rate": error_rate,
                "average_fill_rate": (
                    (total_bits_set / total_capacity) if total_capacity > 0 else 0.0
                ),
            }

            return stats

        except Exception as e:
            logger.error(f"Error calculating Bloom stats: {e}")
            return {}

    def _accumulate_bloom_bits(self, function_blooms: dict[str, BloomFilter]) -> tuple[int, int]:
        total_bits_set = 0
        total_capacity = 0
        for bloom_filter in function_blooms.values():
            if not hasattr(bloom_filter, "bit_array"):
                continue
            bits_set = sum(bloom_filter.bit_array)
            total_bits_set += bits_set
            total_capacity += len(bloom_filter.bit_array)
        return total_bits_set, total_capacity

    def compare_bloom_filters(self, bloom1: BloomFilter, bloom2: BloomFilter) -> float:
        """
        Calculate similarity between two Bloom filters using Jaccard similarity.

        Args:
            bloom1: First Bloom filter
            bloom2: Second Bloom filter

        Returns:
            Similarity score between 0.0 and 1.0
        """
        try:
            if not hasattr(bloom1, "bit_array") or not hasattr(bloom2, "bit_array"):
                return 0.0

            # Calculate Jaccard similarity on bit arrays
            bits1 = {i for i, bit in enumerate(bloom1.bit_array) if bit}
            bits2 = {i for i, bit in enumerate(bloom2.bit_array) if bit}

            if not bits1 and not bits2:
                return 1.0  # Both empty

            if not bits1 or not bits2:
                return 0.0  # One empty

            intersection = len(bits1.intersection(bits2))
            union = len(bits1.union(bits2))

            return intersection / union if union > 0 else 0.0

        except Exception as e:
            logger.error(f"Error comparing Bloom filters: {e}")
            return 0.0

    @staticmethod
    def is_available() -> bool:
        """
        Check if Binbloom analysis is available.

        Returns:
            True if pybloom-live is available
        """
        return BLOOM_AVAILABLE

    @staticmethod
    def deserialize_bloom(bloom_b64: str) -> BloomFilter | None:
        """
        Deserialize a Bloom filter from base64-encoded JSON string.

        SECURITY FIX (CWE-502): This function previously used pickle.loads() which is
        vulnerable to arbitrary code execution attacks. The new implementation uses
        JSON deserialization with explicit type validation, completely eliminating
        the RCE attack surface.

        Defense-in-depth measures:
        1. JSON deserialization only (no arbitrary Python objects)
        2. Explicit type validation for all parameters
        3. Version checking for format compatibility
        4. Range validation for numeric parameters
        5. Secure reconstruction of BloomFilter from validated data

        Args:
            bloom_b64: Base64-encoded JSON string containing Bloom filter parameters

        Returns:
            BloomFilter reconstructed from validated parameters, or None if validation fails

        Raises:
            No exceptions are raised; validation failures return None with error logging
        """
        try:
            # Decode base64 to get JSON string
            json_bytes = base64.b64decode(bloom_b64.encode("utf-8"))
            json_str = json_bytes.decode("utf-8")

            # Parse JSON (safe - cannot execute arbitrary code)
            data = json.loads(json_str)

            # SECURITY: Validate data structure and types
            if not isinstance(data, dict):
                logger.error("Deserialization failed: data is not a dictionary")
                return None

            # Version check for forward compatibility
            version = data.get("version")
            if version != 1:
                logger.error(f"Deserialization failed: unsupported version {version}")
                return None

            # SECURITY: Validate and sanitize all parameters with explicit type conversion
            try:
                error_rate = float(data["error_rate"])
                capacity = int(data["capacity"])
                count = int(data["count"])
                bitarray_list = data["bitarray"]
            except (KeyError, TypeError, ValueError) as e:
                logger.error(f"Deserialization failed: invalid parameter - {e}")
                return None

            # SECURITY: Validate parameter ranges to prevent resource exhaustion
            if not (0.0 < error_rate < 1.0):
                logger.error(f"Deserialization failed: invalid error_rate {error_rate}")
                return None

            if not (1 <= capacity <= 1000000):  # Reasonable limits
                logger.error(f"Deserialization failed: invalid capacity {capacity}")
                return None

            if not (0 <= count <= capacity):
                logger.error(f"Deserialization failed: invalid count {count}")
                return None

            # SECURITY: Validate bitarray is a list of booleans/integers
            if not isinstance(bitarray_list, list):
                logger.error("Deserialization failed: bitarray is not a list")
                return None

            # Reconstruct BloomFilter with validated parameters
            # This creates a new BloomFilter with proper hash functions
            bloom_filter = BloomFilter(capacity=capacity, error_rate=error_rate)

            # Import bitarray here to reconstruct the bit array
            from bitarray import bitarray

            bloom_filter.bitarray = bitarray(bitarray_list)
            bloom_filter.count = count

            logger.debug(
                f"Successfully deserialized Bloom filter (capacity={capacity}, count={count})"
            )
            return bloom_filter

        except json.JSONDecodeError as e:
            logger.error(f"Deserialization failed: invalid JSON - {e}")
            return None
        except Exception as e:
            logger.error(f"Deserialization failed: {e}")
            return None

    @staticmethod
    def calculate_binbloom_from_file(
        filepath: str,
        capacity: int | None = None,
        error_rate: float | None = None,
    ) -> dict[str, Any | None]:
        """
        Calculate Binbloom signatures directly from a file path.

        Args:
            filepath: Path to the binary file
            capacity: Bloom filter capacity
            error_rate: False positive rate

        Returns:
            Binbloom analysis results or None if calculation fails
        """
        try:
            import r2pipe

            with r2pipe.open(filepath, flags=["-2"]) as r2:
                analyzer = BinbloomAnalyzer(r2, filepath)
                return analyzer.analyze(capacity, error_rate)

        except Exception as e:
            logger.error(f"Error calculating Binbloom from file: {e}")
            return None
