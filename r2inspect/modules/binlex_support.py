"""Helper operations for Binlex analyzer."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from ..domain.formats.similarity import jaccard_similarity


def collect_function_signatures(
    analyzer: Any, functions: list[dict[str, Any]], ngram_sizes: list[int]
) -> tuple[dict[str, dict[int, dict[str, Any]]], defaultdict[int, Counter[str]], int]:
    function_signatures: dict[str, dict[int, dict[str, Any]]] = {}
    all_ngrams: defaultdict[int, Counter[str]] = defaultdict(Counter)
    analyzed_count = 0
    for func in functions:
        func_name = func.get("name", f"func_{func.get('addr', 'unknown')}")
        func_addr = func.get("addr")
        if func_addr is None:
            continue
        func_sigs = analyzer._analyze_function(func_addr, func_name, ngram_sizes)
        if not func_sigs:
            continue
        function_signatures[func_name] = func_sigs
        analyzed_count += 1
        analyzer._accumulate_ngrams(all_ngrams, func_sigs, ngram_sizes)
    return function_signatures, all_ngrams, analyzed_count


def accumulate_ngrams(
    all_ngrams: defaultdict[int, Counter[str]],
    func_sigs: dict[int, dict[str, Any]],
    ngram_sizes: list[int],
) -> None:
    for n in ngram_sizes:
        if n not in func_sigs or "ngrams" not in func_sigs[n]:
            continue
        ngrams_value = func_sigs[n].get("ngrams")
        if not isinstance(ngrams_value, list):
            continue
        for ngram in ngrams_value:
            all_ngrams[n][ngram] += 1


def build_signature_groups(
    analyzer: Any,
    function_signatures: dict[str, dict[int, dict[str, Any]]],
    ngram_sizes: list[int],
) -> tuple[dict[int, int], dict[int, list[dict[str, Any]]]]:
    unique_signatures: dict[int, int] = {}
    similar_functions: dict[int, list[dict[str, Any]]] = {}
    for n in ngram_sizes:
        signatures, signature_groups = analyzer._collect_signatures_for_size(function_signatures, n)
        unique_signatures[n] = len(signatures)
        similar_groups = analyzer._build_similar_groups(signature_groups)
        similar_groups.sort(key=lambda x: int(x["count"]), reverse=True)
        similar_functions[n] = similar_groups
    return unique_signatures, similar_functions


def collect_signatures_for_size(
    function_signatures: dict[str, dict[int, dict[str, Any]]], n: int
) -> tuple[set[str], defaultdict[str, list[str]]]:
    signatures: set[str] = set()
    signature_groups: defaultdict[str, list[str]] = defaultdict(list)
    for func_name, func_sigs in function_signatures.items():
        if n not in func_sigs or "signature" not in func_sigs[n]:
            continue
        sig_value = func_sigs[n].get("signature")
        if isinstance(sig_value, str):
            signatures.add(sig_value)
            signature_groups[sig_value].append(func_name)
    return signatures, signature_groups


def build_similar_groups(signature_groups: defaultdict[str, list[str]]) -> list[dict[str, Any]]:
    similar_groups: list[dict[str, Any]] = []
    for sig, funcs in signature_groups.items():
        if len(funcs) > 1:
            similar_groups.append(
                {
                    "signature": sig[:16] + "..." if len(sig) > 16 else sig,
                    "functions": funcs,
                    "count": len(funcs),
                }
            )
    return similar_groups


def collect_top_ngrams(
    all_ngrams: defaultdict[int, Counter[str]], ngram_sizes: list[int]
) -> dict[int, list[tuple[str, int]]]:
    top_ngrams: dict[int, list[tuple[str, int]]] = {}
    for n in ngram_sizes:
        if n in all_ngrams:
            top_ngrams[n] = all_ngrams[n].most_common(10)
    return top_ngrams


def get_function_similarity_score(func1_ngrams: list[str], func2_ngrams: list[str]) -> float:
    set1 = set(func1_ngrams)
    set2 = set(func2_ngrams)
    if not set1 and not set2:
        return 1.0
    if not set1 or not set2:
        return 0.0
    return jaccard_similarity(set1, set2)
