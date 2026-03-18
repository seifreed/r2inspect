#!/usr/bin/env python3
"""Executive summary builders for result aggregation."""

from __future__ import annotations

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


def _count_suspicious_imports(imports: list[dict[str, Any]]) -> int:
    """Count imported APIs commonly associated with suspicious execution flows."""
    return sum(1 for imp in imports if imp.get("name") in SUSPICIOUS_IMPORT_APIS)


def _count_high_entropy_sections(sections: list[dict[str, Any]]) -> int:
    """Count sections whose entropy is high enough to look packed or obfuscated."""
    return sum(1 for section in sections if section.get("entropy", 0) > 7.0)


def _count_suspicious_sections(sections: list[dict[str, Any]]) -> int:
    """Count sections flagged as suspicious by name or recorded indicators."""
    return sum(
        1
        for section in sections
        if section.get("suspicious_indicators") or section.get("name") in SUSPICIOUS_SECTION_NAMES
    )


def _count_crypto_indicators(crypto: dict[str, Any]) -> int:
    """Count crypto-related matches present in the analysis payload."""
    return len(crypto.get("matches", []))


def build_file_overview(analysis_results: dict[str, Any]) -> dict[str, Any]:
    """Build the high-level file identity section of the executive summary."""
    file_info = analysis_results["file_info"]
    pe_info = analysis_results["pe_info"]
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
    rich_header = analysis_results["rich_header"]
    if rich_header.get("available") and rich_header.get("compilers"):
        overview["toolset"] = [
            f"{c.get('compiler_name', 'Unknown')} (Build {c.get('build_number', 0)})"
            for c in rich_header["compilers"][:3]
        ]
    return overview


def build_security_assessment(analysis_results: dict[str, Any]) -> dict[str, Any]:
    """Build the security posture section for the executive summary."""
    security = analysis_results["security"]
    packer = analysis_results["packer"]
    return {
        "is_signed": security.get("authenticode", False),
        "is_packed": packer.get("is_packed", False),
        "packer_type": packer.get("packer_type") if packer.get("is_packed") else None,
        "security_features": {
            "aslr": security.get("aslr", False),
            "dep": security.get("dep", False),
            "cfg": security.get("cfg", False),
            "stack_canary": security.get("stack_canary", False),
            "safe_seh": security.get("safe_seh", False),
        },
    }


def build_threat_indicators(analysis_results: dict[str, Any]) -> dict[str, Any]:
    """Build the threat-indicator section from imports, sections, YARA and crypto."""
    return {
        "suspicious_imports": _count_suspicious_imports(analysis_results["imports"]),
        "yara_matches": len(analysis_results["yara_matches"]),
        "entropy_warnings": _count_high_entropy_sections(analysis_results["sections"]),
        "suspicious_sections": _count_suspicious_sections(analysis_results["sections"]),
        "crypto_indicators": _count_crypto_indicators(analysis_results["crypto"]),
    }


def build_technical_details(analysis_results: dict[str, Any]) -> dict[str, Any]:
    """Build the technical-detail section of the executive summary."""
    return {
        "imports": len(analysis_results["imports"]),
        "sections": len(analysis_results["sections"]),
        "functions": analysis_results["functions"].get("count", 0),
        "crypto_matches": len(analysis_results["crypto"].get("matches", [])),
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
