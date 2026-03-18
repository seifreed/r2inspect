#!/usr/bin/env python3
"""Indicator rules and generators for result aggregation."""

from __future__ import annotations

from typing import Any


def indicator_rules() -> list[Any]:
    return [
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


def generate_indicators(results: dict[str, Any], rules: list[Any]) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []
    for predicate, builder in rules:
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
