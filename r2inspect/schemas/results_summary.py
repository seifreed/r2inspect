"""Serialization and summary helpers for results models."""

from __future__ import annotations

from typing import Any


def analysis_result_to_dict(result: Any) -> dict[str, Any]:
    return {
        "file_info": result.file_info.to_dict(),
        "hashing": result.hashing.to_dict(),
        "security": result.security.to_dict(),
        "imports": [imp.to_dict() for imp in result.imports],
        "exports": [exp.to_dict() for exp in result.exports],
        "sections": [sec.to_dict() for sec in result.sections],
        "strings": result.strings,
        "yara_matches": [match.to_dict() for match in result.yara_matches],
        "functions": [func.to_dict() for func in result.functions],
        "anti_analysis": result.anti_analysis.to_dict(),
        "packer": result.packer.to_dict(),
        "crypto": result.crypto.to_dict(),
        "indicators": [ind.to_dict() for ind in result.indicators],
        "error": result.error,
        "timestamp": result.timestamp.isoformat(),
        "execution_time": result.execution_time,
    }


def is_suspicious(result: Any) -> bool:
    return (
        len(result.indicators) > 0 or result.anti_analysis.has_evasion() or result.packer.is_packed
    )


def high_severity_indicators(result: Any) -> list[Any]:
    return [ind for ind in result.indicators if ind.severity in ("High", "Critical")]


def build_summary(result: Any) -> dict[str, Any]:
    high = high_severity_indicators(result)
    return {
        "file_name": result.file_info.name,
        "file_type": result.file_info.file_type,
        "file_size": result.file_info.size,
        "md5": result.file_info.md5,
        "sha256": result.file_info.sha256,
        "is_packed": result.packer.is_packed,
        "packer_type": result.packer.packer_type if result.packer.is_packed else None,
        "has_crypto": result.crypto.has_crypto(),
        "has_evasion": result.anti_analysis.has_evasion(),
        "security_score": result.security.security_score(),
        "total_imports": len(result.imports),
        "total_exports": len(result.exports),
        "total_sections": len(result.sections),
        "yara_matches_count": len(result.yara_matches),
        "indicators_count": len(result.indicators),
        "high_severity_count": len(high),
    }
