#!/usr/bin/env python3
"""Executive summary builders for result aggregation."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .result_aggregator_recommendation_support import (
    RECOMMENDATION_RULES,
    generate_recommendations,
)

SUSPICIOUS_IMPORT_APIS = {
    "VirtualAlloc",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "SetThreadContext",
}
SUSPICIOUS_SECTION_NAMES = {".textbss", ".data2", ".rsrc", "UPX0", "UPX1"}
SUMMARY_BUILDERS = {
    "file_overview": "build_file_overview",
    "security_assessment": "build_security_assessment",
    "threat_indicators": "build_threat_indicators",
    "technical_details": "build_technical_details",
}


def _dict_bucket(analysis_results: dict[str, Any], key: str) -> dict[str, Any]:
    value = analysis_results.get(key)
    return value if isinstance(value, dict) else {}


def _list_bucket(analysis_results: dict[str, Any], key: str) -> list[Any]:
    value = analysis_results.get(key)
    if isinstance(value, list):
        return value
    if isinstance(value, (dict, str, bytes)) or not isinstance(value, Iterable):
        return []
    return list(value)


def _coerce_float(value: Any) -> float | None:
    try:
        if isinstance(value, str) and not value.strip():
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _count_suspicious_imports(imports: list[dict[str, Any]]) -> int:
    """Count imported APIs commonly associated with suspicious execution flows.

    Matches as a substring so decorated/extended variants (e.g. ``VirtualAllocEx``)
    are counted, consistent with ``categorize_apis``; exact equality silently
    missed the cross-process ``*Ex`` forms, which are the more suspicious ones.
    """
    return sum(
        1
        for imp in imports
        if isinstance(imp, dict)
        and isinstance(name := imp.get("name"), str)
        and any(api in name for api in SUSPICIOUS_IMPORT_APIS)
    )


def _count_high_entropy_sections(sections: list[dict[str, Any]]) -> int:
    """Count sections whose entropy is high enough to look packed or obfuscated."""
    return sum(
        1
        for section in sections
        if isinstance(section, dict)
        and (entropy := _coerce_float(section.get("entropy"))) is not None
        and entropy > 7.0
    )


def _count_suspicious_sections(sections: list[dict[str, Any]]) -> int:
    """Count sections flagged as suspicious by name or recorded indicators."""
    return sum(
        1
        for section in sections
        if isinstance(section, dict)
        and (
            section.get("suspicious_indicators")
            or (
                isinstance(name := section.get("name"), str)
                and name in SUSPICIOUS_SECTION_NAMES
            )
        )
    )


def _count_crypto_indicators(crypto: dict[str, Any]) -> int:
    """Count crypto-related matches present in the analysis payload."""
    matches = crypto.get("matches", [])
    if isinstance(matches, list):
        match_count = len(matches)
    elif isinstance(matches, (dict, str, bytes)) or not isinstance(matches, Iterable):
        match_count = 0
    else:
        match_count = sum(1 for _ in matches)
    if match_count:
        return match_count
    total = 0
    for key in ("algorithms", "constants", "functions"):
        value = crypto.get(key, [])
        if isinstance(value, list):
            total += len(value)
        elif not isinstance(value, (dict, str, bytes)) and isinstance(value, Iterable):
            total += sum(1 for _ in value)
    return total


def build_file_overview(analysis_results: dict[str, Any]) -> dict[str, Any]:
    """Build the high-level file identity section of the executive summary."""
    file_info = _dict_bucket(analysis_results, "file_info")
    pe_info = _dict_bucket(analysis_results, "pe_info")
    overview = {
        "filename": file_info.get("name", "Unknown"),
        "file_type": file_info.get("file_type", "Unknown"),
        "size": file_info.get("size", 0),
        "architecture": file_info.get("architecture", "Unknown"),
        "md5": file_info.get("md5", "Unknown"),
        "sha256": file_info.get("sha256", "Unknown"),
    }
    if "compilation_timestamp" in pe_info:
        overview["compiled"] = pe_info["compilation_timestamp"]
    rich_header = _dict_bucket(analysis_results, "rich_header")
    if rich_header.get("available") and rich_header.get("compilers"):
        compilers = rich_header.get("compilers", [])
        if isinstance(compilers, list):
            normalized_compilers = compilers
        elif isinstance(compilers, (dict, str, bytes)) or not isinstance(compilers, Iterable):
            normalized_compilers = []
        else:
            normalized_compilers = list(compilers)
        toolset = [
            f"{c.get('compiler_name', 'Unknown')} (Build {c.get('build_number', 0)})"
            for c in normalized_compilers[:3]
            if isinstance(c, dict)
        ]
        if toolset:
            overview["toolset"] = toolset
    return overview


def build_security_assessment(analysis_results: dict[str, Any]) -> dict[str, Any]:
    """Build the security posture section for the executive summary."""
    security = _dict_bucket(analysis_results, "security")
    packer = _dict_bucket(analysis_results, "packer")
    return {
        "is_signed": security.get("authenticode", False),
        "is_packed": packer.get("is_packed", False),
        "packer_type": packer.get("packer_type") if packer.get("is_packed") else None,
        "security_features": {
            "aslr": security.get("aslr", False),
            "dep": security.get("dep", False),
            "cfg": security.get("guard_cf", security.get("cfg", False)),
            "stack_canary": security.get("stack_canary", False),
            "safe_seh": security.get("seh", security.get("safe_seh", False)),
        },
    }


def build_threat_indicators(analysis_results: dict[str, Any]) -> dict[str, Any]:
    """Build the threat-indicator section from imports, sections, YARA and crypto."""
    return {
        "suspicious_imports": _count_suspicious_imports(_list_bucket(analysis_results, "imports")),
        "yara_matches": len(_list_bucket(analysis_results, "yara_matches")),
        "entropy_warnings": _count_high_entropy_sections(_list_bucket(analysis_results, "sections")),
        "suspicious_sections": _count_suspicious_sections(_list_bucket(analysis_results, "sections")),
        "crypto_indicators": _count_crypto_indicators(_dict_bucket(analysis_results, "crypto")),
    }


def build_technical_details(analysis_results: dict[str, Any]) -> dict[str, Any]:
    """Build the technical-detail section of the executive summary."""
    functions = _dict_bucket(analysis_results, "functions")
    crypto = _dict_bucket(analysis_results, "crypto")
    function_count = functions.get("count", 0)
    if not function_count:
        raw_functions = analysis_results.get("functions")
        if isinstance(raw_functions, list):
            function_count = len(raw_functions)
    return {
        "imports": len(_list_bucket(analysis_results, "imports")),
        "sections": len(_list_bucket(analysis_results, "sections")),
        "functions": function_count,
        "crypto_matches": _count_crypto_indicators(crypto),
    }


def summary_builders() -> dict[str, Any]:
    """Return the canonical executive-summary builder mapping."""
    builders = {key: globals()[builder_name] for key, builder_name in SUMMARY_BUILDERS.items()}
    builders["recommendations"] = generate_recommendations
    return builders


def generate_executive_summary(results: dict[str, Any], builders: dict[str, Any]) -> dict[str, Any]:
    """Execute the provided builder mapping and collect the summary payload."""
    return {key: builder(results) for key, builder in builders.items()}


__all__ = [
    "RECOMMENDATION_RULES",
    "build_file_overview",
    "build_security_assessment",
    "build_technical_details",
    "build_threat_indicators",
    "generate_executive_summary",
    "generate_recommendations",
    "summary_builders",
]
