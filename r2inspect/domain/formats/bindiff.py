#!/usr/bin/env python3
"""Domain helpers for binary diff analysis."""

from __future__ import annotations

from typing import Any

from .bindiff_compare import (
    calculate_overall_similarity as _calculate_overall_similarity_impl,
    compare_behavioral_features as _compare_behavioral_features_impl,
    compare_byte_features as _compare_byte_features_impl,
    compare_function_features as _compare_function_features_impl,
    compare_rolling_hashes as _compare_rolling_hashes_impl,
    compare_string_features as _compare_string_features_impl,
    compare_structural_features as _compare_structural_features_impl,
)
from .bindiff_indicator import (
    CRYPTO_APIS,
    CRYPTO_TERMS,
    NETWORK_APIS,
    NETWORK_TERMS,
    PERSIST_TERMS,
    SUSPICIOUS_APIS,
    build_behavioral_signature as _build_behavioral_signature_impl,
    build_function_signature as _build_function_signature_impl,
    build_string_signature as _build_string_signature_impl,
    build_struct_signature as _build_struct_signature_impl,
    has_crypto_indicators as _has_crypto_indicators_impl,
    has_network_indicators as _has_network_indicators_impl,
    has_persistence_indicators as _has_persistence_indicators_impl,
    is_crypto_api as _is_crypto_api_impl,
    is_network_api as _is_network_api_impl,
    is_suspicious_api as _is_suspicious_api_impl,
)


def calculate_cyclomatic_complexity(cfg: dict[str, Any]) -> int:
    try:
        edges = len(cfg.get("edges", []))
        nodes = len(cfg.get("blocks", []))
        return edges - nodes + 2 if nodes > 0 else 0
    except (TypeError, AttributeError, KeyError):
        return 0


def calculate_rolling_hash(data: bytes, window_size: int = 64) -> list[int]:
    import hashlib

    hashes: list[int] = []
    for i in range(len(data) - window_size + 1):
        window = data[i : i + window_size]
        # Use MD5 truncated to 32 bits for deterministic, reproducible hashing
        # (hash() uses PYTHONHASHSEED which varies between runs)
        # Not used for security purposes - only for binary diffing
        digest = hashlib.md5(window, usedforsecurity=False).digest()
        hashes.append(int.from_bytes(digest[:4], "little"))
    return hashes[:100]


def compare_rolling_hashes(a_hashes: list[int], b_hashes: list[int]) -> float:
    return _compare_rolling_hashes_impl(a_hashes, b_hashes)


def categorize_similarity(score: float) -> str:
    if score >= 0.8:
        return "Very High"
    if score >= 0.6:
        return "High"
    if score >= 0.4:
        return "Medium"
    if score >= 0.2:
        return "Low"
    return "Very Low"


def has_crypto_indicators(text: str) -> bool:
    return _has_crypto_indicators_impl(text)


def has_network_indicators(text: str) -> bool:
    return _has_network_indicators_impl(text)


def has_persistence_indicators(text: str) -> bool:
    return _has_persistence_indicators_impl(text)


def is_suspicious_api(api: str) -> bool:
    return _is_suspicious_api_impl(api)


def is_crypto_api(api: str) -> bool:
    return _is_crypto_api_impl(api)


def is_network_api(api: str) -> bool:
    return _is_network_api_impl(api)


def build_struct_signature(struct_features: dict[str, Any]) -> str:
    return _build_struct_signature_impl(struct_features)


def build_function_signature(func_features: dict[str, Any]) -> str:
    return _build_function_signature_impl(func_features)


def build_string_signature(string_features: dict[str, Any]) -> str:
    return _build_string_signature_impl(string_features)


def build_behavioral_signature(behavioral_features: dict[str, Any]) -> str:
    return _build_behavioral_signature_impl(behavioral_features)


def compare_structural_features(a_struct: dict[str, Any], b_struct: dict[str, Any]) -> float:
    return _compare_structural_features_impl(a_struct, b_struct)


def compare_function_features(a_func: dict[str, Any], b_func: dict[str, Any]) -> float:
    return _compare_function_features_impl(a_func, b_func)


def compare_string_features(a_str: dict[str, Any], b_str: dict[str, Any]) -> float:
    return _compare_string_features_impl(a_str, b_str)


def compare_byte_features(a_bytes: dict[str, Any], b_bytes: dict[str, Any]) -> float:
    return _compare_byte_features_impl(a_bytes, b_bytes)


def compare_behavioral_features(a_behav: dict[str, Any], b_behav: dict[str, Any]) -> float:
    return _compare_behavioral_features_impl(a_behav, b_behav)


def calculate_overall_similarity(
    structural: float,
    function: float,
    string: float,
    byte: float,
    behavioral: float,
) -> float:
    return _calculate_overall_similarity_impl(structural, function, string, byte, behavioral)
