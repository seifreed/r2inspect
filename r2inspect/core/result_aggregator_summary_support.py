#!/usr/bin/env python3
"""Executive summary builders for result aggregation."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..abstractions.coercion_support import (
    coerce_list,
    coerce_number_or_none,
    get_dict_bucket,
    get_list_bucket,
)
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
        and (entropy := coerce_number_or_none(section.get("entropy"))) is not None
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
            or (isinstance(name := section.get("name"), str) and name in SUSPICIOUS_SECTION_NAMES)
        )
    )


def _iterable_count(value: Any) -> int:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, (dict, str, bytes)) or not isinstance(value, Iterable):
        return 0
    return sum(1 for _ in value)


def _count_crypto_indicators(crypto: dict[str, Any]) -> int:
    """Count crypto-related matches present in the analysis payload."""
    match_count = _iterable_count(crypto.get("matches", []))
    if match_count:
        return match_count
    return sum(
        _iterable_count(crypto.get(key, [])) for key in ("algorithms", "constants", "functions")
    )


def build_file_overview(analysis_results: dict[str, Any]) -> dict[str, Any]:
    """Build the high-level file identity section of the executive summary."""
    file_info = analysis_results.get("file_info")
    if file_info is None:
        file_info = {}
    elif not isinstance(file_info, dict):
        raise TypeError("file_info must be a dict or None")
    pe_info = get_dict_bucket(analysis_results, "pe_info")
    overview = {
        "filename": file_info.get("name", "Unknown"),
        "file_type": file_info.get("file_type", "Unknown"),
        "size": file_info.get("size", 0),
        "architecture": file_info.get("architecture", "Unknown"),
        "md5": file_info.get("md5", "Unknown"),
        "sha256": file_info.get("sha256", "Unknown"),
    }
    compiled = pe_info.get("compile_time", pe_info.get("compilation_timestamp"))
    if compiled:
        overview["compiled"] = compiled
    toolset = _compiler_toolset(get_dict_bucket(analysis_results, "rich_header"))
    if toolset:
        overview["toolset"] = toolset
    return overview


def _compiler_toolset(rich_header: dict[str, Any]) -> list[str]:
    if not (rich_header.get("available") and rich_header.get("compilers")):
        return []
    normalized_compilers = coerce_list(rich_header.get("compilers", []))
    return [
        f"{c.get('compiler_name', 'Unknown')} (Build {c.get('build_number', 0)})"
        for c in normalized_compilers[:3]
        if isinstance(c, dict)
    ]


def build_security_assessment(analysis_results: dict[str, Any]) -> dict[str, Any]:
    """Build the security posture section for the executive summary."""
    security = get_dict_bucket(analysis_results, "security")
    packer = get_dict_bucket(analysis_results, "packer")
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
        "suspicious_imports": _count_suspicious_imports(
            get_list_bucket(analysis_results, "imports")
        ),
        "yara_matches": len(get_list_bucket(analysis_results, "yara_matches")),
        "entropy_warnings": _count_high_entropy_sections(
            get_list_bucket(analysis_results, "sections")
        ),
        "suspicious_sections": _count_suspicious_sections(
            get_list_bucket(analysis_results, "sections")
        ),
        "crypto_indicators": _count_crypto_indicators(get_dict_bucket(analysis_results, "crypto")),
    }


def build_technical_details(analysis_results: dict[str, Any]) -> dict[str, Any]:
    """Build the technical-detail section of the executive summary."""
    functions = get_dict_bucket(analysis_results, "functions")
    crypto = get_dict_bucket(analysis_results, "crypto")
    # function_analyzer emits the count under "total_functions"; "count" is kept
    # as a fallback for hand-built result dicts.
    function_count = functions.get("total_functions") or functions.get("count", 0)
    if not function_count:
        raw_functions = analysis_results.get("functions")
        if isinstance(raw_functions, list):
            function_count = len(raw_functions)
    return {
        "imports": len(get_list_bucket(analysis_results, "imports")),
        "sections": len(get_list_bucket(analysis_results, "sections")),
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
