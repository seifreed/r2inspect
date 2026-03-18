#!/usr/bin/env python3
"""Binbloom-style function fingerprinting."""

from __future__ import annotations

from typing import Any, TypedDict, cast

from ..abstractions import BaseAnalyzer
from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..adapters.analyzer_runner import run_analyzer_on_file
from ..infrastructure.logging import get_logger
from .binbloom_mixin import BinbloomMixin

logger = get_logger(__name__)

# Try to import pybloom_live, fall back to error handling
try:
    from pybloom_live import BloomFilter

    BLOOM_AVAILABLE = True
except ImportError:
    logger.warning("pybloom-live not available. Install with: pip install pybloom-live")
    BLOOM_AVAILABLE = False
    BloomFilter = None


class BinbloomResult(TypedDict):
    available: bool
    analyzer: str
    library_available: bool
    function_blooms: dict[str, Any]
    function_signatures: dict[str, Any]
    total_functions: int
    analyzed_functions: int
    capacity: int
    error_rate: float
    binary_bloom: str | None
    binary_signature: str | None
    similar_functions: list[dict[str, Any]]
    unique_signatures: int
    bloom_stats: dict[str, Any]
    error: str | None
    execution_time: float


class BinbloomAnalyzer(BinbloomMixin, CommandHelperMixin, BaseAnalyzer):
    """Bloom filter-based function analysis."""

    def __init__(self, adapter: Any, filepath: str) -> None:
        """Initialize analyzer state."""
        super().__init__(adapter=adapter, filepath=filepath)
        self.default_capacity = 256  # Default Bloom filter capacity
        self.default_error_rate = 0.001  # 0.1% false positive rate

    def analyze(  # type: ignore[override]
        self, capacity: int | None = None, error_rate: float | None = None
    ) -> BinbloomResult:
        """Analyze functions using Bloom filters."""
        from .binbloom_analysis import run_binbloom_analysis

        return cast(
            BinbloomResult,
            run_binbloom_analysis(
                analyzer=self,
                capacity=capacity,
                error_rate=error_rate,
                bloom_available=BLOOM_AVAILABLE,
                log_debug=logger.debug,
                log_error=logger.error,
            ),
        )

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
        results: BinbloomResult,
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
        """Extract all functions from the binary."""

        def _load() -> list[dict[str, Any]]:
            if self.adapter is not None and hasattr(self.adapter, "analyze_all"):
                self.adapter.analyze_all()
            functions = self._cmd_list("aflj")
            if not functions:
                logger.debug("No functions found with 'aflj' command")
                return []
            valid = [f for f in functions if f.get("addr") is not None and f.get("size", 0) > 0]
            logger.debug("Extracted %s valid functions", len(valid))
            return valid

        return self._safe_call(_load, default=[], error_msg="Error extracting functions")

    def _create_function_bloom(
        self, func_addr: int, func_name: str, capacity: int, error_rate: float
    ) -> tuple[BloomFilter, list[str], str] | None:
        """Create a Bloom filter for a specific function."""

        def _build() -> tuple[BloomFilter, list[str], str] | None:
            instructions = self._extract_instruction_mnemonics(func_addr, func_name)
            if not instructions:
                logger.debug("No instructions found for function %s", func_name)
                return None
            bloom_filter = self._build_bloom_filter(instructions, capacity, error_rate)
            signature = self._bloom_to_signature(instructions)
            logger.debug(
                "Created Bloom filter for %s: %d instructions, signature: %s...",
                func_name,
                len(instructions),
                signature[:16],
            )
            return bloom_filter, instructions, signature

        return self._safe_call(
            _build,
            default=None,
            error_msg=f"Error creating Bloom filter for function {func_name}",
        )

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
        return BinbloomMixin.deserialize_bloom(bloom_b64)

    @staticmethod
    def calculate_binbloom_from_file(
        filepath: str,
        capacity: int | None = None,
        error_rate: float | None = None,
    ) -> BinbloomResult | None:
        """
        Calculate Binbloom signatures directly from a file path.

        Args:
            filepath: Path to the binary file
            capacity: Bloom filter capacity
            error_rate: False positive rate

        Returns:
            Binbloom analysis results or None if calculation fails
        """
        result = run_analyzer_on_file(BinbloomAnalyzer, filepath, capacity, error_rate)
        if result is None:
            logger.error("Error calculating Binbloom from file")
        return result
