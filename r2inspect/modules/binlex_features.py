"""Feature extraction helpers for Binlex analyzer."""

from __future__ import annotations

from typing import Any, cast


def extract_functions(analyzer: Any, *, logger: Any) -> list[dict[str, Any]]:
    try:
        if analyzer.adapter is not None and hasattr(analyzer.adapter, "analyze_all"):
            analyzer.adapter.analyze_all()
        functions = analyzer._cmd_list("aflj")
        if not functions:
            logger.debug("No functions found with 'aflj' command")
            return []
        valid_functions = []
        for func in functions:
            if func.get("addr") is not None and func.get("size", 0) > 0:
                valid_functions.append(func)
        logger.debug("Extracted %s valid functions", len(valid_functions))
        return valid_functions
    except Exception as exc:
        logger.error("Error extracting functions: %s", exc)
        return []


def analyze_function(
    analyzer: Any, func_addr: int, func_name: str, ngram_sizes: list[int], *, logger: Any
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
    analyzer: Any, func_addr: int, func_name: str, *, logger: Any
) -> list[str]:
    try:
        tokens = analyzer._extract_tokens_from_pdfj(func_addr, func_name)
        if tokens:
            return cast(list[str], tokens)
        tokens = analyzer._extract_tokens_from_pdj(func_addr, func_name)
        if tokens:
            return cast(list[str], tokens)
        tokens = analyzer._extract_tokens_from_text(func_addr, func_name)
        if tokens:
            return cast(list[str], tokens)
    except Exception as exc:
        logger.debug("Error extracting tokens from %s: %s", func_name, exc)
    return []
