#!/usr/bin/env python3
"""Import analysis domain helpers."""

from __future__ import annotations

from collections import Counter
from typing import Any

NETWORK_CATEGORY = "Network/Internet"

INJECTION_APIS: dict[str, tuple[int, str]] = {
    "CreateRemoteThread": (95, "Remote Thread Injection"),
    "WriteProcessMemory": (90, "Process Memory Manipulation"),
    "VirtualAllocEx": (85, "Remote Memory Allocation"),
    "SetThreadContext": (90, "Thread Context Manipulation"),
    "QueueUserAPC": (85, "APC Injection"),
    "NtMapViewOfSection": (90, "Section Mapping Injection"),
}

ANTI_ANALYSIS_APIS: dict[str, tuple[int, str]] = {
    "IsDebuggerPresent": (75, "Anti-Debug"),
    "CheckRemoteDebuggerPresent": (80, "Remote Debug Detection"),
    "NtQueryInformationProcess": (85, "Process Information Query"),
    "QueryPerformanceCounter": (60, "Timing Check"),
    "GetTickCount": (50, "Timing Check"),
    "OutputDebugString": (65, "Debug String Check"),
}

CRYPTO_APIS: dict[str, tuple[int, str]] = {
    "CryptEncrypt": (70, "Data Encryption"),
    "CryptDecrypt": (65, "Data Decryption"),
    "CryptCreateHash": (55, "Hash Creation"),
    "BCryptEncrypt": (75, "Modern Encryption"),
    "CryptGenKey": (60, "Key Generation"),
}

PERSISTENCE_APIS: dict[str, tuple[int, str]] = {
    "CreateService": (80, "Service Creation"),
    "SetWindowsHookEx": (75, "Hook Installation"),
    "RegSetValueEx": (65, "Registry Modification"),
    "CopyFile": (40, "File Copy"),
    "MoveFile": (35, "File Move"),
}

NETWORK_APIS: dict[str, tuple[int, str]] = {
    "URLDownloadToFile": (70, "File Download"),
    "InternetOpen": (50, "Internet Access"),
    "WinHttpSendRequest": (60, "HTTP Request"),
    "socket": (45, "Network Socket"),
    "connect": (50, "Network Connection"),
}

PROCESS_APIS: dict[str, tuple[int, str]] = {
    "CreateProcess": (65, "Process Creation"),
    "OpenProcess": (60, "Process Access"),
    "TerminateProcess": (70, "Process Termination"),
    "CreateThread": (45, "Thread Creation"),
    "SuspendThread": (55, "Thread Suspension"),
}

MEMORY_APIS: dict[str, tuple[int, str]] = {
    "VirtualAlloc": (50, "Memory Allocation"),
    "VirtualProtect": (65, "Memory Protection Change"),
    "HeapAlloc": (30, "Heap Allocation"),
    "MapViewOfFile": (55, "File Mapping"),
}

LOADING_APIS: dict[str, tuple[int, str]] = {
    "LoadLibrary": (45, "Dynamic Library Loading"),
    "GetProcAddress": (50, "Function Address Resolution"),
    "FreeLibrary": (25, "Library Unloading"),
}

ALL_RISK_API_CATEGORIES: tuple[str, ...] = (
    "INJECTION_APIS",
    "ANTI_ANALYSIS_APIS",
    "CRYPTO_APIS",
    "PERSISTENCE_APIS",
    "NETWORK_APIS",
    "PROCESS_APIS",
    "MEMORY_APIS",
    "LOADING_APIS",
)


def build_api_categories() -> dict[str, dict[str, tuple[int, str]]]:
    return {
        "Injection": INJECTION_APIS,
        "Anti-Analysis": ANTI_ANALYSIS_APIS,
        "Crypto": CRYPTO_APIS,
        "Persistence": PERSISTENCE_APIS,
        "Network": NETWORK_APIS,
        "Process": PROCESS_APIS,
        "Memory": MEMORY_APIS,
        "Loading": LOADING_APIS,
    }


def categorize_apis(
    imports: list[dict[str, Any]], api_categories: dict[str, list[str]]
) -> dict[str, Any]:
    categories: dict[str, Any] = {}
    for category, apis in api_categories.items():
        category_count = 0
        category_apis = []
        for imp in imports:
            api_name = imp.get("name", "")
            if any(api.lower() in api_name.lower() for api in apis):
                category_count += 1
                category_apis.append(api_name)
        if category_count > 0:
            categories[category] = {"count": category_count, "apis": category_apis}
    return categories


def assess_api_risk(categories: dict[str, Any]) -> tuple[list[str], int]:
    suspicious_apis: list[str] = []
    risk_score = 0
    if categories.get("Anti-Analysis", {}).get("count", 0) >= 2:
        suspicious_apis.append("Multiple anti-debug APIs detected")
        risk_score += 20
    if categories.get("DLL Injection", {}).get("count", 0) >= 3:
        suspicious_apis.append("DLL injection pattern detected")
        risk_score += 30
    process_count = categories.get("Process/Thread Management", {}).get("count", 0)
    memory_count = categories.get("Memory Management", {}).get("count", 0)
    if process_count >= 3 and memory_count >= 3:
        suspicious_apis.append("Process manipulation pattern detected")
        risk_score += 25
    if categories.get("Registry", {}).get("count", 0) >= 4:
        suspicious_apis.append("Extensive registry manipulation")
        risk_score += 15
    if categories.get(NETWORK_CATEGORY, {}).get("count", 0) >= 3:
        suspicious_apis.append("Network communication capabilities")
        risk_score += 10
    return suspicious_apis, risk_score


def _count_matching(names: list[str], apis: list[str]) -> int:
    """Count import names that match any of the given API patterns."""
    return sum(1 for name in names if any(api in name for api in apis))


def _detect_injection_patterns(patterns: list[dict[str, Any]], names: list[str]) -> None:
    """Detect DLL injection, process hollowing, and keylogging patterns."""
    injection = _count_matching(
        names, ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
    )
    if injection >= 2:
        patterns.append(
            {
                "pattern": "DLL Injection",
                "description": "APIs commonly used for DLL injection detected",
                "severity": "High",
                "count": injection,
            }
        )

    hollowing = _count_matching(
        names,
        [
            "CreateProcess",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "SetThreadContext",
            "ResumeThread",
        ],
    )
    if hollowing >= 3:
        patterns.append(
            {
                "pattern": "Process Hollowing",
                "description": "APIs commonly used for process hollowing detected",
                "severity": "High",
                "count": hollowing,
            }
        )

    keylog = _count_matching(names, ["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState"])
    if keylog >= 1:
        patterns.append(
            {
                "pattern": "Keylogging",
                "description": "Potential keylogging capabilities detected",
                "severity": "Medium",
                "count": keylog,
            }
        )


def _detect_category_patterns(patterns: list[dict[str, Any]], categories: list[str]) -> None:
    """Detect suspicious patterns based on import category counts."""
    for category, threshold, label, severity in (
        (NETWORK_CATEGORY, 5, "Heavy Network Usage", "Medium"),
        ("Anti-Analysis", 0, "Anti-Analysis", "High"),
        ("Cryptography", 3, "Heavy Cryptography", "Medium"),
    ):
        count = categories.count(category)
        if count > threshold:
            patterns.append(
                {
                    "pattern": label,
                    "description": f"{label} APIs detected ({count})",
                    "severity": severity,
                    "count": count,
                }
            )


def find_suspicious_patterns(imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect suspicious API usage patterns in the import table."""
    patterns: list[dict[str, Any]] = []
    names = [imp.get("name", "") for imp in imports]
    categories = [imp.get("category", "") for imp in imports]
    _detect_injection_patterns(patterns, names)
    _detect_category_patterns(patterns, categories)
    return patterns


def count_import_categories(imports: list[dict[str, Any]]) -> dict[str, int]:
    category_counts: Counter[str] = Counter()
    for imp in imports:
        category = imp.get("category")
        if category:
            category_counts[category] += 1
    return dict(category_counts)


def find_max_risk_score(
    func_name: str, categories: dict[str, dict[str, tuple[int, str]]]
) -> tuple[int, list[str]]:
    max_score = 0
    tags: list[str] = []
    for api_dict in categories.values():
        for api_name, (score, tag) in api_dict.items():
            if api_name in func_name:
                if score > max_score:
                    max_score = score
                    tags = [tag]
                elif score == max_score:
                    tags.append(tag)
    return max_score, tags


def risk_level_from_score(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 45:
        return "Medium"
    if score >= 25:
        return "Low"
    return "Minimal"
