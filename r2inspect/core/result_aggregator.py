#!/usr/bin/env python3
"""Result aggregation helpers for executive summaries and indicators."""

from typing import Any

from ..utils.logger import get_logger

logger = get_logger(__name__)

_DEFAULTS: dict[str, Any] = {
    "file_info": {},
    "pe_info": {},
    "security": {},
    "packer": {},
    "anti_analysis": {},
    "imports": [],
    "yara_matches": [],
    "sections": [],
    "functions": {},
    "crypto": {},
    "rich_header": {},
}


def _normalize_results(analysis_results: dict[str, Any]) -> dict[str, Any]:
    return {key: analysis_results.get(key, default) for key, default in _DEFAULTS.items()}


def _build_file_overview(analysis_results: dict[str, Any]) -> dict[str, Any]:
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
        compilers = rich_header["compilers"][:3]
        overview["toolset"] = [
            f"{c.get('compiler_name', 'Unknown')} (Build {c.get('build_number', 0)})"
            for c in compilers
        ]

    return overview


def _build_security_assessment(analysis_results: dict[str, Any]) -> dict[str, Any]:
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


def _build_threat_indicators(analysis_results: dict[str, Any]) -> dict[str, Any]:
    return {
        "suspicious_imports": _count_suspicious_imports(analysis_results["imports"]),
        "yara_matches": len(analysis_results["yara_matches"]),
        "entropy_warnings": _count_high_entropy_sections(analysis_results["sections"]),
        "suspicious_sections": _count_suspicious_sections(analysis_results["sections"]),
        "crypto_indicators": _count_crypto_indicators(analysis_results["crypto"]),
    }


def _build_technical_details(analysis_results: dict[str, Any]) -> dict[str, Any]:
    return {
        "imports": len(analysis_results["imports"]),
        "sections": len(analysis_results["sections"]),
        "functions": analysis_results["functions"].get("count", 0),
        "crypto_matches": len(analysis_results["crypto"].get("matches", [])),
    }


def _count_suspicious_imports(imports: list[dict[str, Any]]) -> int:
    suspicious_apis = {
        "VirtualAlloc",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "SetThreadContext",
    }
    return sum(1 for imp in imports if imp.get("name") in suspicious_apis)


def _count_high_entropy_sections(sections: list[dict[str, Any]]) -> int:
    return sum(1 for section in sections if section.get("entropy", 0) > 7.0)


def _count_suspicious_sections(sections: list[dict[str, Any]]) -> int:
    suspicious_names = {".textbss", ".data2", ".rsrc", "UPX0", "UPX1"}
    return sum(
        1
        for section in sections
        if section.get("suspicious_indicators") or section.get("name") in suspicious_names
    )


def _count_crypto_indicators(crypto: dict[str, Any]) -> int:
    return len(crypto.get("matches", []))


def _generate_recommendations(analysis_results: dict[str, Any]) -> list[str]:
    recommendations = [
        message for predicate, message in _RECOMMENDATION_RULES if predicate(analysis_results)
    ]
    return recommendations or ["No immediate concerns detected; proceed with standard analysis."]


_INDICATOR_RULES = [
    (
        lambda results: results["packer"].get("is_packed"),
        lambda results: {
            "type": "Packer",
            "description": "File appears to be packed with "
            f"{results['packer'].get('packer_type', 'Unknown')}",
            "severity": "Medium",
        },
    ),
    (
        lambda results: results["anti_analysis"].get("anti_debug"),
        lambda _results: {
            "type": "Anti-Debug",
            "description": "Anti-debugging techniques detected",
            "severity": "High",
        },
    ),
    (
        lambda results: results["anti_analysis"].get("anti_vm"),
        lambda _results: {
            "type": "Anti-VM",
            "description": "Anti-virtualization techniques detected",
            "severity": "High",
        },
    ),
]

_RECOMMENDATION_RULES = [
    (
        lambda results: results["packer"].get("is_packed"),
        "File appears packed; consider unpacking before deeper analysis.",
    ),
    (
        lambda results: results["security"].get("authenticode") is False,
        "File is unsigned; verify source and integrity.",
    ),
    (
        lambda results: results["crypto"].get("matches"),
        "Cryptographic routines detected; check for encryption or obfuscation.",
    ),
    (
        lambda results: results["anti_analysis"].get("anti_debug"),
        "Anti-debugging detected; use anti-anti-debug techniques.",
    ),
]

_SUMMARY_BUILDERS = {
    "file_overview": _build_file_overview,
    "security_assessment": _build_security_assessment,
    "threat_indicators": _build_threat_indicators,
    "technical_details": _build_technical_details,
    "recommendations": _generate_recommendations,
}


class ResultAggregator:
    """Aggregates analysis results and generates summaries."""

    def generate_indicators(self, analysis_results: dict[str, Any]) -> list[dict[str, Any]]:
        results = _normalize_results(analysis_results)
        indicators: list[dict[str, Any]] = []

        for predicate, builder in _INDICATOR_RULES:
            if predicate(results):
                indicators.append(builder(results))

        suspicious_apis = {
            "VirtualAlloc",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "SetThreadContext",
        }
        indicators.extend(
            {
                "type": "Suspicious API",
                "description": f"Suspicious API call: {imp.get('name')}",
                "severity": "Medium",
            }
            for imp in results["imports"]
            if imp.get("name") in suspicious_apis
        )

        indicators.extend(
            {
                "type": "YARA Match",
                "description": f"YARA rule matched: {match.get('rule', 'Unknown')}",
                "severity": "High",
            }
            for match in results["yara_matches"]
        )

        return indicators

    def generate_executive_summary(self, analysis_results: dict[str, Any]) -> dict[str, Any]:
        try:
            results = _normalize_results(analysis_results)
            return {key: builder(results) for key, builder in _SUMMARY_BUILDERS.items()}
        except Exception as exc:
            logger.error(f"Error generating executive summary: {exc}")
            return {"error": str(exc)}


__all__ = ["ResultAggregator"]
