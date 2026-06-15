"""Feature extraction helpers for Binlex analyzer."""

from __future__ import annotations

import logging

from typing import Any

from .binlex_support import BinlexHost
from .function_extraction import collect_valid_functions


def extract_functions(analyzer: BinlexHost, *, logger: logging.Logger) -> list[dict[str, Any]]:
    try:
        return collect_valid_functions(analyzer, logger, run_analyze_all=True)
    except Exception as exc:
        logger.error("Error extracting functions: %s", exc)
        return []


def analyze_function(
    analyzer: BinlexHost,
    func_addr: int,
    func_name: str,
    ngram_sizes: list[int],
    *,
    logger: logging.Logger,
) -> dict[int, dict[str, Any | None]] | None:
    try:
        tokens = analyzer._extract_instruction_tokens(func_addr, func_name)
        if not tokens:
            logger.debug("No tokens found for function %s", func_name)
            return None
        results: dict[int, dict[str, Any | None]] = {}
        for n in ngram_sizes:
            if len(tokens) < n:
                logger.debug(
                    "Function %s has too few tokens (%s) for %s-gram analysis",
                    func_name,
                    len(tokens),
                    n,
                )
                continue
            ngrams = analyzer._generate_ngrams(tokens, n)
            if not ngrams:
                continue
            signature = analyzer._create_signature(ngrams)
            results[n] = {
                "signature": signature,
                "ngrams": ngrams,
                "token_count": len(tokens),
                "ngram_count": len(ngrams),
                "unique_ngrams": len(set(ngrams)),
            }
        return results if results else None
    except Exception as exc:
        logger.debug("Error analyzing function %s: %s", func_name, exc)
        return None


def extract_instruction_tokens(
    analyzer: BinlexHost, func_addr: int, func_name: str, *, logger: logging.Logger
) -> list[str]:
    try:
        tokens = analyzer._extract_tokens_from_pdfj(func_addr, func_name)
        if tokens:
            return tokens
        tokens = analyzer._extract_tokens_from_pdj(func_addr, func_name)
        if tokens:
            return tokens
        tokens = analyzer._extract_tokens_from_text(func_addr, func_name)
        if tokens:
            return tokens
    except Exception as exc:
        logger.debug("Error extracting tokens from %s: %s", func_name, exc)
    return []
