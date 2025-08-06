#!/usr/bin/env python3
"""
Binlex Analyzer Module

This module implements Binlex-style byte-level lexical hashing for function analysis.
Binlex creates signatures based on n-grams of instruction mnemonics, which is useful for:
- Function similarity detection
- Malware family clustering
- Variant analysis across different compilation environments

Based on the Binlex approach for lexical analysis of binary functions.
"""

import hashlib
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmd_list, safe_cmdj

logger = get_logger(__name__)

# Constants
HTML_NBSP = "&nbsp;"
HTML_AMP = "&amp;"


class BinlexAnalyzer:
    """Binlex-style lexical analysis of binary functions"""

    def __init__(self, r2_instance, filepath: str):
        """
        Initialize Binlex analyzer.

        Args:
            r2_instance: Active r2pipe instance
            filepath: Path to the binary file being analyzed
        """
        self.r2 = r2_instance
        self.filepath = filepath
        self.default_ngram_size = 3  # Default n-gram size

    def analyze(self, ngram_sizes: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Perform Binlex analysis on all functions in the binary.

        Args:
            ngram_sizes: List of n-gram sizes to analyze (default: [2, 3, 4])

        Returns:
            Dictionary containing Binlex analysis results
        """
        if ngram_sizes is None:
            ngram_sizes = [2, 3, 4]

        logger.debug(f"Starting Binlex analysis for {self.filepath}")

        results = {
            "available": False,
            "function_signatures": {},
            "ngram_sizes": ngram_sizes,
            "total_functions": 0,
            "analyzed_functions": 0,
            "unique_signatures": {},
            "similar_functions": {},
            "binary_signature": None,
            "top_ngrams": {},
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

            # Analyze functions for each n-gram size
            function_signatures = {}
            all_ngrams = defaultdict(Counter)  # Track all n-grams across functions
            analyzed_count = 0

            for func in functions:
                func_name = func.get("name", f"func_{func.get('addr', 'unknown')}")
                func_addr = func.get("addr")

                if func_addr is None:
                    continue

                # Extract function signatures for all n-gram sizes
                func_sigs = self._analyze_function(func_addr, func_name, ngram_sizes)
                if func_sigs:
                    function_signatures[func_name] = func_sigs
                    analyzed_count += 1

                    # Collect n-grams for global analysis
                    for n in ngram_sizes:
                        if n in func_sigs and "ngrams" in func_sigs[n]:
                            for ngram in func_sigs[n]["ngrams"]:
                                all_ngrams[n][ngram] += 1

            if not function_signatures:
                results["error"] = "No functions could be analyzed for Binlex"
                logger.debug("No functions could be analyzed for Binlex")
                return results

            # Analyze results
            results["available"] = True
            results["function_signatures"] = function_signatures
            results["analyzed_functions"] = analyzed_count

            # Calculate unique signatures for each n-gram size
            unique_signatures = {}
            similar_functions = {}

            for n in ngram_sizes:
                # Count unique signatures
                signatures = set()
                signature_groups = defaultdict(list)

                for func_name, func_sigs in function_signatures.items():
                    if n in func_sigs and "signature" in func_sigs[n]:
                        sig = func_sigs[n]["signature"]
                        signatures.add(sig)
                        signature_groups[sig].append(func_name)

                unique_signatures[n] = len(signatures)

                # Find similar functions (same signature)
                similar_groups = []
                for sig, funcs in signature_groups.items():
                    if len(funcs) > 1:
                        similar_groups.append(
                            {
                                "signature": sig[:16] + "..." if len(sig) > 16 else sig,
                                "functions": funcs,
                                "count": len(funcs),
                            }
                        )

                # Sort by group size
                similar_groups.sort(key=lambda x: x["count"], reverse=True)
                similar_functions[n] = similar_groups

            results["unique_signatures"] = unique_signatures
            results["similar_functions"] = similar_functions

            # Calculate binary-wide signature
            binary_signature = self._calculate_binary_signature(function_signatures, ngram_sizes)
            results["binary_signature"] = binary_signature

            # Get top n-grams for each size
            top_ngrams = {}
            for n in ngram_sizes:
                if n in all_ngrams:
                    # Get top 10 most common n-grams
                    top_ngrams[n] = all_ngrams[n].most_common(10)
            results["top_ngrams"] = top_ngrams

            logger.debug(
                f"Binlex analysis completed: {analyzed_count}/{len(functions)} functions analyzed"
            )

        except Exception as e:
            logger.error(f"Binlex analysis failed: {e}")
            results["error"] = str(e)

        return results

    def _extract_functions(self) -> List[Dict[str, Any]]:
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

    def _analyze_function(
        self, func_addr: int, func_name: str, ngram_sizes: List[int]
    ) -> Optional[Dict[int, Dict[str, Any]]]:
        """
        Analyze a single function with Binlex for multiple n-gram sizes.

        Args:
            func_addr: Function address
            func_name: Function name for logging
            ngram_sizes: List of n-gram sizes to analyze

        Returns:
            Dictionary with analysis results for each n-gram size
        """
        try:
            # Seek to function
            self.r2.cmd(f"s {func_addr}")

            # Extract instruction tokens
            tokens = self._extract_instruction_tokens(func_name)
            if not tokens:
                logger.debug(f"No tokens found for function {func_name}")
                return None

            # Analyze for each n-gram size
            results = {}
            for n in ngram_sizes:
                if len(tokens) < n:
                    logger.debug(
                        f"Function {func_name} has too few tokens ({len(tokens)}) for {n}-gram analysis"
                    )
                    continue

                # Generate n-grams
                ngrams = self._generate_ngrams(tokens, n)
                if not ngrams:
                    continue

                # Create signature
                signature = self._create_signature(ngrams)

                results[n] = {
                    "signature": signature,
                    "ngrams": ngrams,
                    "token_count": len(tokens),
                    "ngram_count": len(ngrams),
                    "unique_ngrams": len(set(ngrams)),
                }

            return results if results else None

        except Exception as e:
            logger.debug(f"Error analyzing function {func_name}: {e}")
            return None

    def _extract_instruction_tokens(self, func_name: str) -> List[str]:
        """
        Extract instruction tokens (mnemonics) from current function.

        Args:
            func_name: Function name for logging

        Returns:
            List of instruction mnemonics
        """
        tokens = []

        try:
            # Method 1: Try pdfj (print disassembly function JSON)
            disasm = safe_cmdj(self.r2, "pdfj", {})
            if disasm and "ops" in disasm:
                for op in disasm["ops"]:
                    if isinstance(op, dict):
                        # Try different fields for mnemonic
                        mnemonic = op.get("mnemonic")
                        if not mnemonic and "opcode" in op:
                            opcode = op["opcode"].strip()
                            if opcode:
                                mnemonic = opcode.split()[0]

                        if mnemonic:
                            # Clean and normalize mnemonic
                            clean_mnemonic = mnemonic.strip().lower()
                            # Remove any HTML entities or special characters
                            clean_mnemonic = clean_mnemonic.replace(HTML_NBSP, " ").replace(
                                HTML_AMP, "&"
                            )
                            # Only add if it looks like a valid instruction
                            if clean_mnemonic and not clean_mnemonic.startswith("&"):
                                tokens.append(clean_mnemonic)

                if tokens:
                    logger.debug(f"Extracted {len(tokens)} tokens from {func_name} using pdfj")
                    return tokens

            # Method 2: Try pdj with instruction limit
            disasm_list = safe_cmd_list(self.r2, "pdj 200")  # Limit to 200 instructions
            if isinstance(disasm_list, list):
                for op in disasm_list:
                    if isinstance(op, dict):
                        # Try different fields for mnemonic
                        mnemonic = op.get("mnemonic")
                        if not mnemonic and "opcode" in op:
                            opcode = op["opcode"].strip()
                            if opcode:
                                mnemonic = opcode.split()[0]

                        if mnemonic:
                            # Clean and normalize mnemonic
                            clean_mnemonic = mnemonic.strip().lower()
                            # Remove any HTML entities or special characters
                            clean_mnemonic = clean_mnemonic.replace(HTML_NBSP, " ").replace(
                                HTML_AMP, "&"
                            )
                            # Only add if it looks like a valid instruction
                            if clean_mnemonic and not clean_mnemonic.startswith("&"):
                                tokens.append(clean_mnemonic)

                if tokens:
                    logger.debug(f"Extracted {len(tokens)} tokens from {func_name} using pdj")
                    return tokens

            # Method 3: Fallback to text-based extraction
            instructions_text = self.r2.cmd("pi 100")  # Get up to 100 instructions
            if instructions_text and instructions_text.strip():
                lines = instructions_text.strip().split("\n")
                for line in lines:
                    line = line.strip()
                    if line:
                        # Extract mnemonic (first word)
                        mnemonic = line.split()[0]
                        if mnemonic:
                            # Clean and normalize mnemonic
                            clean_mnemonic = mnemonic.strip().lower()
                            # Remove any HTML entities or special characters
                            clean_mnemonic = clean_mnemonic.replace(HTML_NBSP, " ").replace(
                                HTML_AMP, "&"
                            )
                            # Only add if it looks like a valid instruction
                            if clean_mnemonic and not clean_mnemonic.startswith("&"):
                                tokens.append(clean_mnemonic)

                if tokens:
                    logger.debug(f"Extracted {len(tokens)} tokens from {func_name} using pi")
                    return tokens

        except Exception as e:
            logger.debug(f"Error extracting tokens from {func_name}: {e}")

        return tokens

    def _generate_ngrams(self, tokens: List[str], n: int) -> List[str]:
        """
        Generate n-grams from token sequence.

        Args:
            tokens: List of instruction tokens
            n: N-gram size

        Returns:
            List of n-gram strings
        """
        if len(tokens) < n:
            return []

        ngrams = []
        for i in range(len(tokens) - n + 1):
            ngram = " ".join(tokens[i : i + n])
            ngrams.append(ngram)

        return ngrams

    def _create_signature(self, ngrams: List[str]) -> str:
        """
        Create a signature hash from n-grams.

        Args:
            ngrams: List of n-gram strings

        Returns:
            SHA256 signature hash
        """
        # Sort n-grams for canonical representation
        sorted_ngrams = sorted(ngrams)
        combined = "|".join(sorted_ngrams)

        # Create SHA256 hash
        signature = hashlib.sha256(combined.encode("utf-8")).hexdigest()
        return signature

    def _calculate_binary_signature(
        self,
        function_signatures: Dict[str, Dict[int, Dict[str, Any]]],
        ngram_sizes: List[int],
    ) -> Dict[int, str]:
        """
        Calculate binary-wide signatures by combining all function signatures.

        Args:
            function_signatures: Dictionary of function signatures
            ngram_sizes: List of n-gram sizes

        Returns:
            Dictionary of binary signatures for each n-gram size
        """
        binary_signatures = {}

        try:
            for n in ngram_sizes:
                # Collect all signatures for this n-gram size
                signatures = []
                for func_name, func_sigs in function_signatures.items():
                    if n in func_sigs and "signature" in func_sigs[n]:
                        signatures.append(func_sigs[n]["signature"])

                if signatures:
                    # Sort for canonical representation
                    sorted_signatures = sorted(signatures)
                    combined = "|".join(sorted_signatures)

                    # Create binary signature
                    binary_sig = hashlib.sha256(combined.encode("utf-8")).hexdigest()
                    binary_signatures[n] = binary_sig

        except Exception as e:
            logger.error(f"Error calculating binary signature: {e}")

        return binary_signatures

    def compare_functions(self, func1_sig: str, func2_sig: str) -> bool:
        """
        Compare two function signatures for exact match.

        Args:
            func1_sig: First function signature
            func2_sig: Second function signature

        Returns:
            True if signatures match exactly
        """
        return func1_sig == func2_sig

    def get_function_similarity_score(
        self, func1_ngrams: List[str], func2_ngrams: List[str]
    ) -> float:
        """
        Calculate similarity score between two functions based on n-gram overlap.

        Args:
            func1_ngrams: N-grams from first function
            func2_ngrams: N-grams from second function

        Returns:
            Similarity score between 0.0 and 1.0
        """
        try:
            set1 = set(func1_ngrams)
            set2 = set(func2_ngrams)

            if not set1 and not set2:
                return 1.0  # Both empty

            if not set1 or not set2:
                return 0.0  # One empty

            # Jaccard similarity
            intersection = len(set1.intersection(set2))
            union = len(set1.union(set2))

            return intersection / union if union > 0 else 0.0

        except Exception as e:
            logger.error(f"Error calculating similarity score: {e}")
            return 0.0

    @staticmethod
    def is_available() -> bool:
        """
        Check if Binlex analysis is available.
        Always returns True as it only depends on r2pipe.

        Returns:
            True if Binlex analysis is available
        """
        return True

    @staticmethod
    def calculate_binlex_from_file(
        filepath: str, ngram_sizes: Optional[List[int]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Calculate Binlex signatures directly from a file path.

        Args:
            filepath: Path to the binary file
            ngram_sizes: List of n-gram sizes to analyze

        Returns:
            Binlex analysis results or None if calculation fails
        """
        try:
            import r2pipe

            with r2pipe.open(filepath, flags=["-2"]) as r2:
                analyzer = BinlexAnalyzer(r2, filepath)
                return analyzer.analyze(ngram_sizes)

        except Exception as e:
            logger.error(f"Error calculating Binlex from file: {e}")
            return None
