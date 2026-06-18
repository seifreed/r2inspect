#!/usr/bin/env python3
"""Import analysis domain helpers."""

from __future__ import annotations

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
        if not isinstance(apis, (list, tuple, set)):
            continue
        category_count = 0
        category_apis = []
        valid_apis = [api for api in apis if isinstance(api, str)]
        for imp in imports:
            if not isinstance(imp, dict):
                continue
            api_name = imp.get("name", "")
            if not isinstance(api_name, str):
                continue
            if any(api.lower() in api_name.lower() for api in valid_apis):
                category_count += 1
                category_apis.append(api_name)
        if category_count > 0:
            categories[category] = {"count": category_count, "apis": category_apis}
    return categories


def assess_api_risk(categories: dict[str, Any]) -> tuple[list[str], int]:
    suspicious_apis: list[str] = []
    risk_score = 0
    if _category_count(categories, "Anti-Analysis") >= 2:
        suspicious_apis.append("Multiple anti-debug APIs detected")
        risk_score += 20
    if _category_count(categories, "DLL Injection", "Injection") >= 3:
        suspicious_apis.append("DLL injection pattern detected")
        risk_score += 30
    process_count = _category_count(categories, "Process/Thread Management", "Process")
    memory_count = _category_count(categories, "Memory Management", "Memory")
    if process_count >= 3 and memory_count >= 3:
        suspicious_apis.append("Process manipulation pattern detected")
        risk_score += 25
    if _category_count(categories, "Registry", "Persistence") >= 4:
        suspicious_apis.append("Extensive registry manipulation")
        risk_score += 15
    if _category_count(categories, NETWORK_CATEGORY, "Network") >= 3:
        suspicious_apis.append("Network communication capabilities")
        risk_score += 10
    return suspicious_apis, risk_score


def _category_count(categories: dict[str, Any], *names: str) -> int:
    for name in names:
        value = categories.get(name)
        if isinstance(value, dict):
            count = value.get("count", 0)
            if isinstance(count, int):
                return count
    return 0


def find_max_risk_score(
    func_name: str, categories: dict[str, dict[str, tuple[int, str]]]
) -> tuple[int, list[str]]:
    max_score = 0
    tags: list[str] = []
    if not isinstance(categories, dict):
        return max_score, tags
    for api_dict in categories.values():
        if not isinstance(api_dict, dict):
            continue
        for api_name, api_data in api_dict.items():
            if not isinstance(api_data, tuple) or len(api_data) < 2:
                continue
            score, tag = api_data[:2]
            if not isinstance(score, int) or not isinstance(tag, str):
                continue
            if api_name in func_name:
                if score > max_score:
                    max_score = score
                    tags = [tag]
                elif score == max_score:
                    tags.append(tag)
    return max_score, tags


def risk_level_from_score(score: int) -> str:
    try:
        score = int(score)
    except (TypeError, ValueError):
        score = 0
    if score >= 80:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 45:
        return "Medium"
    if score >= 25:
        return "Low"
    return "Minimal"
