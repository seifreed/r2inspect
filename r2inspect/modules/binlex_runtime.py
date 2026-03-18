"""Runtime workflow helpers for Binlex analyzer."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, cast

from ..adapters.analyzer_runner import run_analyzer_on_file
from ..domain.services.binlex import (
    calculate_binary_signature,
    extract_tokens_from_ops,
    extract_tokens_from_text,
)


def run_binlex_analysis(
    analyzer: Any,
    *,
    ngram_sizes: list[int] | None,
    logger: Any,
) -> dict[str, Any]:
    if ngram_sizes is None:
        ngram_sizes = [2, 3, 4]

    logger.debug("Starting Binlex analysis for %s", analyzer.filepath)
    results = cast(
        dict[str, Any],
        analyzer._init_result_structure(
            {
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
        ),
    )
    try:
        functions = analyzer._extract_functions()
        if not functions:
            results["error"] = "No functions found in binary"
            logger.debug("No functions found in binary")
            return results

        results["total_functions"] = len(functions)
        function_signatures, all_ngrams, analyzed_count = analyzer._collect_function_signatures(
            functions,
            ngram_sizes,
        )
        if not function_signatures:
            results["error"] = "No functions could be analyzed for Binlex"
            logger.debug("No functions could be analyzed for Binlex")
            return results

        results["available"] = True
        results["function_signatures"] = function_signatures
        results["analyzed_functions"] = analyzed_count
        unique_signatures, similar_functions = analyzer._build_signature_groups(
            function_signatures,
            ngram_sizes,
        )
        results["unique_signatures"] = unique_signatures
        results["similar_functions"] = similar_functions
        results["binary_signature"] = calculate_binary_signature_safe(
            function_signatures,
            ngram_sizes,
            logger=logger,
        )
        results["top_ngrams"] = analyzer._collect_top_ngrams(all_ngrams, ngram_sizes)
        logger.debug(
            f"Binlex analysis completed: {analyzed_count}/{len(functions)} functions analyzed"
        )
    except Exception as e:
        logger.error("Binlex analysis failed: %s", e)
        results["error"] = str(e)
    return results


def extract_tokens_from_pdfj(
    analyzer: Any, func_addr: int, func_name: str, *, logger: Any
) -> list[str]:
    disasm = (
        analyzer.adapter.get_disasm(address=func_addr)
        if analyzer.adapter is not None and hasattr(analyzer.adapter, "get_disasm")
        else analyzer._cmdj("pdfj", {})
    )
    if not disasm or "ops" not in disasm:
        return []
    tokens = extract_tokens_from_ops(disasm["ops"])
    if tokens:
        logger.debug("Extracted %s tokens from %s using pdfj", len(tokens), func_name)
    return tokens


def extract_tokens_from_pdj(
    analyzer: Any, func_addr: int, func_name: str, *, logger: Any
) -> list[str]:
    disasm_list = (
        analyzer.adapter.get_disasm(address=func_addr, size=200)
        if analyzer.adapter is not None and hasattr(analyzer.adapter, "get_disasm")
        else analyzer._cmd_list("pdj 200")
    )
    if not isinstance(disasm_list, list):
        return []
    tokens = extract_tokens_from_ops(disasm_list)
    if tokens:
        logger.debug("Extracted %s tokens from %s using pdj", len(tokens), func_name)
    return tokens


def extract_tokens_from_text_channel(
    analyzer: Any,
    func_addr: int,
    func_name: str,
    *,
    logger: Any,
) -> list[str]:
    instructions_text = (
        analyzer.adapter.get_disasm_text(address=func_addr, size=100)
        if analyzer.adapter is not None and hasattr(analyzer.adapter, "get_disasm_text")
        else analyzer._cmd("pi 100")
    )
    tokens = extract_tokens_from_text(instructions_text or "")
    if tokens:
        logger.debug("Extracted %s tokens from %s using pi", len(tokens), func_name)
    return tokens


def calculate_binary_signature_safe(
    function_signatures: dict[str, dict[int, dict[str, Any]]],
    ngram_sizes: list[int],
    *,
    logger: Any,
) -> dict[int, str]:
    try:
        return calculate_binary_signature(function_signatures, ngram_sizes)
    except Exception as e:
        logger.error("Error calculating binary signature: %s", e)
        return {}


def get_function_similarity_score_safe(
    func1_ngrams: list[str],
    func2_ngrams: list[str],
    similarity_impl: Any,
    *,
    logger: Any,
) -> float:
    try:
        return float(similarity_impl(func1_ngrams, func2_ngrams))
    except Exception as e:
        logger.error("Error calculating similarity score: %s", e)
        return 0.0


def calculate_binlex_from_file(
    analyzer_cls: type[Any],
    filepath: str,
    ngram_sizes: list[int] | None,
    *,
    logger: Any,
) -> dict[str, Any] | None:
    result = run_analyzer_on_file(analyzer_cls, filepath, ngram_sizes)
    if result is None:
        logger.error("Error calculating Binlex from file")
    return result
