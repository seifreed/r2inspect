#!/usr/bin/env python3
"""Indicator rules and generators for result aggregation."""

from __future__ import annotations

from typing import Any

from ..abstractions.coercion_support import coerce_list


def indicator_rules() -> list[Any]:
    return [
        (
            lambda results: isinstance((packer := results.get("packer")), dict)
            and packer.get("is_packed"),
            lambda results: {
                "type": "Packer",
                "description": "File appears to be packed with "
                f"{results.get('packer', {}).get('packer_type', 'Unknown')}",
                "severity": "Medium",
            },
        ),
        (
            lambda results: isinstance((anti_analysis := results.get("anti_analysis")), dict)
            and anti_analysis.get("anti_debug"),
            lambda _results: {
                "type": "Anti-Debug",
                "description": "Anti-debugging techniques detected",
                "severity": "High",
            },
        ),
        (
            lambda results: isinstance((anti_analysis := results.get("anti_analysis")), dict)
            and anti_analysis.get("anti_vm"),
            lambda _results: {
                "type": "Anti-VM",
                "description": "Anti-virtualization techniques detected",
                "severity": "High",
            },
        ),
    ]


_SUSPICIOUS_APIS = {
    "VirtualAlloc",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "SetThreadContext",
}


def _suspicious_api_indicators(imports: Any) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []
    for imp in coerce_list(imports):
        if not isinstance(imp, dict):
            continue
        name = imp.get("name") or ""
        if any(api in name for api in _SUSPICIOUS_APIS):
            indicators.append(
                {
                    "type": "Suspicious API",
                    "description": f"Suspicious API call: {name}",
                    "severity": "Medium",
                }
            )
    return indicators


def _yara_match_indicators(yara_matches: Any) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []
    for match in coerce_list(yara_matches):
        if not isinstance(match, dict):
            continue
        indicators.append(
            {
                "type": "YARA Match",
                "description": f"YARA rule matched: {match.get('rule', 'Unknown')}",
                "severity": "High",
            }
        )
    return indicators


def generate_indicators(results: dict[str, Any], rules: list[Any]) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []
    for predicate, builder in rules:
        if predicate(results):
            indicators.append(builder(results))
    indicators.extend(_suspicious_api_indicators(results.get("imports", [])))
    indicators.extend(_yara_match_indicators(results.get("yara_matches", [])))
    return indicators
