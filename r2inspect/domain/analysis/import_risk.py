"""Pure domain logic for import risk analysis.

This module contains pure functions for import risk scoring
with no infrastructure dependencies (stdlib only).
"""

from __future__ import annotations

from typing import Any


def get_risk_level(total_risk: float) -> str:
    """Convert numerical risk score to risk level string."""
    if total_risk >= 70:
        return "HIGH"
    if total_risk >= 40:
        return "MEDIUM"
    return "LOW"


def count_suspicious_indicators(result: dict[str, Any]) -> int:
    """Count total suspicious indicators in analysis result."""
    api_analysis = result.get("api_analysis", {})
    obfuscation = result.get("obfuscation", {})
    anomalies = result.get("anomalies", {})
    return (
        len(api_analysis.get("suspicious_apis", []))
        + len(obfuscation.get("indicators", []))
        + int(anomalies.get("count", 0))
    )


def get_function_description(func_name: str) -> str:
    """Get human-readable description for common API functions."""
    descriptions = {
        "CreateProcess": "Creates a new process",
        "CreateRemoteThread": "Creates thread in another process (DLL injection)",
        "WriteProcessMemory": "Writes to another process memory",
        "VirtualAlloc": "Allocates virtual memory",
        "VirtualAllocEx": "Allocates memory in another process",
        "LoadLibrary": "Loads a DLL dynamically",
        "GetProcAddress": "Gets address of exported function",
        "RegSetValue": "Sets registry value",
        "CreateFile": "Creates or opens file",
        "IsDebuggerPresent": "Checks if debugger is present",
        "CreateService": "Creates a Windows service",
        "CryptEncrypt": "Encrypts data",
        "InternetOpen": "Initializes WinINet",
        "URLDownloadToFile": "Downloads file from URL",
    }
    for api, desc in descriptions.items():
        if api in func_name:
            return desc
    return ""


def is_candidate_api_string(string_val: str, imported_apis: list[str]) -> bool:
    """Check if a string is a candidate API name (not already imported)."""
    return (
        len(string_val) > 3
        and string_val[0].isupper()
        and any(c.islower() for c in string_val)
        and string_val not in imported_apis
    )


def matches_known_api(string_val: str, api_categories: dict[str, Any]) -> bool:
    """Check if a string matches any known API in categories."""
    for _, apis in api_categories.items():
        if any(api in string_val for api in apis):
            return True
    return False


__all__ = [
    "get_risk_level",
    "count_suspicious_indicators",
    "get_function_description",
    "is_candidate_api_string",
    "matches_known_api",
]
