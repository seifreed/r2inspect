"""Batch analysis statistics helpers."""

from __future__ import annotations

from typing import Any


def update_packer_stats(stats: dict[str, Any], file_key: str, result: dict[str, Any]) -> None:
    """Update packer statistics."""
    packer = result.get("packer")
    if isinstance(packer, dict) and packer.get("is_packed"):
        stats["packers_detected"].append(
            {
                "file": file_key,
                "packer": packer.get("packer_type") or "Unknown",
            }
        )


def update_crypto_stats(stats: dict[str, Any], file_key: str, result: dict[str, Any]) -> None:
    """Update crypto pattern statistics."""
    crypto = result.get("crypto")
    if isinstance(crypto, dict):
        for algorithm in crypto.get("algorithms", []):
            if not isinstance(algorithm, dict):
                continue
            stats["crypto_patterns"].append(
                {"file": file_key, "pattern": algorithm.get("algorithm", "Unknown")}
            )


def update_indicator_stats(stats: dict[str, Any], file_key: str, result: dict[str, Any]) -> None:
    """Update suspicious indicator statistics."""
    indicators = result.get("indicators")
    if isinstance(indicators, list) and indicators:
        stats["suspicious_indicators"].extend(
            [
                {"file": file_key, **indicator}
                for indicator in indicators
                if isinstance(indicator, dict)
            ]
        )


def update_file_type_stats(stats: dict[str, Any], result: dict[str, Any]) -> None:
    """Update file type and architecture statistics."""
    file_info = result.get("file_info")
    if isinstance(file_info, dict):
        file_type = file_info.get("file_type", "Unknown")
        stats["file_types"][file_type] = stats["file_types"].get(file_type, 0) + 1

        architecture = file_info.get("architecture", "Unknown")
        stats["architectures"][architecture] = stats["architectures"].get(architecture, 0) + 1


def update_compiler_stats(stats: dict[str, Any], result: dict[str, Any]) -> None:
    """Update compiler statistics."""
    compiler_info = result.get("compiler")
    if isinstance(compiler_info, dict):
        compiler_name = compiler_info.get("compiler", "Unknown")
        if compiler_info.get("detected", False):
            stats["compilers"][compiler_name] = stats["compilers"].get(compiler_name, 0) + 1


def collect_batch_statistics(all_results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Collect statistics from batch analysis results."""
    stats: dict[str, Any] = {
        "packers_detected": [],
        "crypto_patterns": [],
        "suspicious_indicators": [],
        "file_types": {},
        "architectures": {},
        "compilers": {},
    }

    for file_key, result in all_results.items():
        update_packer_stats(stats, file_key, result)
        update_crypto_stats(stats, file_key, result)
        update_indicator_stats(stats, file_key, result)
        update_file_type_stats(stats, result)
        update_compiler_stats(stats, result)

    return stats
