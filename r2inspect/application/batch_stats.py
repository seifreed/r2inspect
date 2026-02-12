"""Batch analysis statistics helpers."""

from __future__ import annotations

from typing import Any


def update_packer_stats(stats: dict[str, Any], file_key: str, result: dict[str, Any]) -> None:
    """Update packer statistics."""
    if "packer_info" in result and result["packer_info"].get("detected"):
        stats["packers_detected"].append(
            {
                "file": file_key,
                "packer": result["packer_info"].get("name", "Unknown"),
            }
        )


def update_crypto_stats(stats: dict[str, Any], file_key: str, result: dict[str, Any]) -> None:
    """Update crypto pattern statistics."""
    if "crypto_info" in result and result["crypto_info"]:
        for crypto in result["crypto_info"]:
            stats["crypto_patterns"].append({"file": file_key, "pattern": crypto})


def update_indicator_stats(stats: dict[str, Any], file_key: str, result: dict[str, Any]) -> None:
    """Update suspicious indicator statistics."""
    if "indicators" in result and result["indicators"]:
        stats["suspicious_indicators"].extend(
            [{"file": file_key, **indicator} for indicator in result["indicators"]]
        )


def update_file_type_stats(stats: dict[str, Any], result: dict[str, Any]) -> None:
    """Update file type and architecture statistics."""
    if "file_info" in result:
        file_type = result["file_info"].get("file_type", "Unknown")
        stats["file_types"][file_type] = stats["file_types"].get(file_type, 0) + 1

        architecture = result["file_info"].get("architecture", "Unknown")
        stats["architectures"][architecture] = stats["architectures"].get(architecture, 0) + 1


def update_compiler_stats(stats: dict[str, Any], result: dict[str, Any]) -> None:
    """Update compiler statistics."""
    if "compiler" in result:
        compiler_info = result["compiler"]
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
