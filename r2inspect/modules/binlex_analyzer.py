#!/usr/bin/env python3
"""Binlex lexical analysis for function similarity."""

from collections import Counter, defaultdict
from typing import Any, TypedDict, cast

from ..abstractions import BaseAnalyzer
from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..domain.services.binlex import (
    create_signature,
    extract_mnemonic_from_op,
    extract_tokens_from_ops,
    generate_ngrams,
    normalize_mnemonic,
)
from ..infrastructure.logging import get_logger
from .binlex_support import (
    accumulate_ngrams as _accumulate_ngrams_impl,
    build_signature_groups as _build_signature_groups_impl,
    build_similar_groups as _build_similar_groups_impl,
    collect_function_signatures as _collect_function_signatures_impl,
    collect_signatures_for_size as _collect_signatures_for_size_impl,
    collect_top_ngrams as _collect_top_ngrams_impl,
    get_function_similarity_score as _get_function_similarity_score_impl,
)
from .binlex_features import (
    analyze_function as _analyze_function_impl,
    extract_functions as _extract_functions_impl,
    extract_instruction_tokens as _extract_instruction_tokens_impl,
)
from .binlex_runtime import (
    calculate_binary_signature_safe as _calculate_binary_signature_safe,
    calculate_binlex_from_file as _calculate_binlex_from_file,
    extract_tokens_from_pdfj as _extract_tokens_from_pdfj_impl,
    extract_tokens_from_pdj as _extract_tokens_from_pdj_impl,
    extract_tokens_from_text_channel as _extract_tokens_from_text_impl,
    get_function_similarity_score_safe as _get_function_similarity_score_safe,
    run_binlex_analysis,
)
from ..domain.formats.similarity import jaccard_similarity

logger = get_logger(__name__)


class BinlexResult(TypedDict):
    available: bool
    analyzer: str
    function_signatures: dict[str, dict[int, dict[str, Any]]]
    ngram_sizes: list[int]
    total_functions: int
    analyzed_functions: int
    unique_signatures: dict[int, int]
    similar_functions: dict[int, list[dict[str, Any]]]
    binary_signature: dict[int, str] | None
    top_ngrams: dict[int, list[tuple[str, int]]]
    error: str | None
    execution_time: float


class BinlexAnalyzer(CommandHelperMixin, BaseAnalyzer):
    """Lexical function similarity analysis."""

    def __init__(self, adapter: Any, filepath: str) -> None:
        """Initialize analyzer state."""
        super().__init__(adapter=adapter, filepath=filepath)
        self.default_ngram_size = 3  # Default n-gram size

    def analyze(self, ngram_sizes: list[int] | None = None) -> BinlexResult:  # type: ignore[override]
        """Run Binlex analysis for all functions."""
        return cast(BinlexResult, run_binlex_analysis(self, ngram_sizes=ngram_sizes, logger=logger))

    def _collect_function_signatures(
        self, functions: list[dict[str, Any]], ngram_sizes: list[int]
    ) -> tuple[dict[str, dict[int, dict[str, Any]]], defaultdict[int, Counter[str]], int]:
        return _collect_function_signatures_impl(self, functions, ngram_sizes)

    def _accumulate_ngrams(
        self,
        all_ngrams: defaultdict[int, Counter[str]],
        func_sigs: dict[int, dict[str, Any]],
        ngram_sizes: list[int],
    ) -> None:
        _accumulate_ngrams_impl(all_ngrams, func_sigs, ngram_sizes)

    def _build_signature_groups(
        self,
        function_signatures: dict[str, dict[int, dict[str, Any]]],
        ngram_sizes: list[int],
    ) -> tuple[dict[int, int], dict[int, list[dict[str, Any]]]]:
        return _build_signature_groups_impl(self, function_signatures, ngram_sizes)

    def _collect_signatures_for_size(
        self, function_signatures: dict[str, dict[int, dict[str, Any]]], n: int
    ) -> tuple[set[str], defaultdict[str, list[str]]]:
        return _collect_signatures_for_size_impl(function_signatures, n)

    def _build_similar_groups(
        self, signature_groups: defaultdict[str, list[str]]
    ) -> list[dict[str, Any]]:
        return _build_similar_groups_impl(signature_groups)

    def _collect_top_ngrams(
        self, all_ngrams: defaultdict[int, Counter[str]], ngram_sizes: list[int]
    ) -> dict[int, list[tuple[str, int]]]:
        return _collect_top_ngrams_impl(all_ngrams, ngram_sizes)

    def _extract_functions(self) -> list[dict[str, Any]]:
        """
        Extract all functions from the binary.

        Returns:
            List of function dictionaries
        """
        return _extract_functions_impl(self, logger=logger)

    def _analyze_function(
        self, func_addr: int, func_name: str, ngram_sizes: list[int]
    ) -> dict[int, dict[str, Any | None]] | None:
        """
        Analyze a single function with Binlex for multiple n-gram sizes.

        Args:
            func_addr: Function address
            func_name: Function name for logging
            ngram_sizes: List of n-gram sizes to analyze

        Returns:
            Dictionary with analysis results for each n-gram size
        """
        return _analyze_function_impl(self, func_addr, func_name, ngram_sizes, logger=logger)

    def _extract_instruction_tokens(self, func_addr: int, func_name: str) -> list[str]:
        """
        Extract instruction tokens (mnemonics) from current function.

        Args:
            func_name: Function name for logging

        Returns:
            List of instruction mnemonics
        """
        return _extract_instruction_tokens_impl(self, func_addr, func_name, logger=logger)

    def _extract_tokens_from_pdfj(self, func_addr: int, func_name: str) -> list[str]:
        return _extract_tokens_from_pdfj_impl(self, func_addr, func_name, logger=logger)

    def _extract_tokens_from_pdj(self, func_addr: int, func_name: str) -> list[str]:
        return _extract_tokens_from_pdj_impl(self, func_addr, func_name, logger=logger)

    def _extract_tokens_from_text(self, func_addr: int, func_name: str) -> list[str]:
        return _extract_tokens_from_text_impl(self, func_addr, func_name, logger=logger)

    def _extract_tokens_from_ops(self, ops: list[Any]) -> list[str]:
        return extract_tokens_from_ops(ops)

    def _extract_mnemonic_from_op(self, op: dict[str, Any]) -> str | None:
        return extract_mnemonic_from_op(op)

    def _normalize_mnemonic(self, mnemonic: str | None) -> str | None:
        return normalize_mnemonic(mnemonic)

    def _generate_ngrams(self, tokens: list[str], n: int) -> list[str]:
        """
        Generate n-grams from token sequence.

        Args:
            tokens: List of instruction tokens
            n: N-gram size

        Returns:
            List of n-gram strings
        """
        return generate_ngrams(tokens, n)

    def _create_signature(self, ngrams: list[str]) -> str:
        """
        Create a signature hash from n-grams.

        Args:
            ngrams: List of n-gram strings

        Returns:
            SHA256 signature hash
        """
        return create_signature(ngrams)

    def _calculate_binary_signature(
        self,
        function_signatures: dict[str, dict[int, dict[str, Any]]],
        ngram_sizes: list[int],
    ) -> dict[int, str]:
        return _calculate_binary_signature_safe(function_signatures, ngram_sizes, logger=logger)

    def compare_functions(self, func1_sig: str, func2_sig: str) -> bool:
        """Compare two function signatures for exact match."""
        return func1_sig == func2_sig

    def get_function_similarity_score(
        self, func1_ngrams: list[str], func2_ngrams: list[str]
    ) -> float:
        """Calculate similarity score between two functions based on n-gram overlap."""
        return _get_function_similarity_score_safe(
            func1_ngrams,
            func2_ngrams,
            _get_function_similarity_score_impl,
            logger=logger,
        )

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
        filepath: str, ngram_sizes: list[int] | None = None
    ) -> BinlexResult | None:
        return cast(
            BinlexResult | None,
            _calculate_binlex_from_file(BinlexAnalyzer, filepath, ngram_sizes, logger=logger),
        )
