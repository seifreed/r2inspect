#!/usr/bin/env python3
"""Pure domain helpers for import-table analysis."""

from __future__ import annotations

from collections import Counter
from typing import Any

COMMON_SYSTEM_DLLS = {
    "kernel32.dll",
    "user32.dll",
    "advapi32.dll",
    "ntdll.dll",
    "msvcrt.dll",
    "shell32.dll",
    "ole32.dll",
    "oleaut32.dll",
    "ws2_32.dll",
    "wininet.dll",
    "urlmon.dll",
    "shlwapi.dll",
}

SUSPICIOUS_DLLS = {
    "psapi.dll",
    "imagehlp.dll",
    "dbghelp.dll",
    "winsock.dll",
    "rasapi32.dll",
    "netapi32.dll",
    "secur32.dll",
    "crypt32.dll",
    "wintrust.dll",
    "version.dll",
    "setupapi.dll",
    "cfgmgr32.dll",
}

NETWORK_CATEGORY = "Network/Internet"


def _count_matching_apis(import_names: list[str], apis: list[str]) -> int:
    return sum(1 for name in import_names if any(api in name for api in apis))


def _pattern_entry(pattern: str, description: str, severity: str, count: int) -> dict[str, Any]:
    return {
        "pattern": pattern,
        "description": description,
        "severity": severity,
        "count": count,
    }


def find_suspicious_patterns(imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    patterns: list[dict[str, Any]] = []
    import_names = [imp.get("name", "") for imp in imports]
    categories = [imp.get("category", "") for imp in imports]
    _append_injection_patterns(patterns, import_names)
    _append_behavior_patterns(patterns, import_names, categories)
    return patterns


def _append_injection_patterns(patterns: list[dict[str, Any]], import_names: list[str]) -> None:
    injection_count = _count_matching_apis(
        import_names, ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
    )
    if injection_count >= 2:
        patterns.append(
            _pattern_entry(
                "DLL Injection",
                "APIs commonly used for DLL injection detected",
                "High",
                injection_count,
            )
        )

    hollowing_count = _count_matching_apis(
        import_names,
        [
            "CreateProcess",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "SetThreadContext",
            "ResumeThread",
        ],
    )
    if hollowing_count >= 3:
        patterns.append(
            _pattern_entry(
                "Process Hollowing",
                "APIs commonly used for process hollowing detected",
                "High",
                hollowing_count,
            )
        )

    keylog_count = _count_matching_apis(
        import_names, ["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState"]
    )
    if keylog_count >= 1:
        patterns.append(
            _pattern_entry(
                "Keylogging", "Potential keylogging capabilities detected", "Medium", keylog_count
            )
        )


def _append_behavior_patterns(
    patterns: list[dict[str, Any]], import_names: list[str], categories: list[str]
) -> None:
    del import_names
    for predicate, entry in (
        (
            categories.count(NETWORK_CATEGORY) > 5,
            _pattern_entry(
                "Heavy Network Usage",
                f"Many network-related APIs ({categories.count(NETWORK_CATEGORY)})",
                "Medium",
                categories.count(NETWORK_CATEGORY),
            ),
        ),
        (
            categories.count("Anti-Analysis") > 0,
            _pattern_entry(
                "Anti-Analysis",
                f"Anti-analysis APIs detected ({categories.count('Anti-Analysis')})",
                "High",
                categories.count("Anti-Analysis"),
            ),
        ),
        (
            categories.count("Cryptography") > 3,
            _pattern_entry(
                "Heavy Cryptography",
                f"Many cryptographic APIs ({categories.count('Cryptography')})",
                "Medium",
                categories.count("Cryptography"),
            ),
        ),
    ):
        if predicate:
            patterns.append(entry)


def build_import_statistics(imports: list[dict[str, Any]]) -> dict[str, Any]:
    stats = {
        "total_imports": 0,
        "unique_libraries": 0,
        "category_distribution": {},
        "risk_distribution": {},
        "library_distribution": {},
        "suspicious_patterns": [],
    }
    if not imports:
        return stats

    valid_imports = [imp for imp in imports if isinstance(imp, dict)]
    categories = [imp.get("category", "Unknown") for imp in valid_imports]
    risks = [imp.get("risk_level", "Unknown") for imp in valid_imports]
    libraries = [
        imp.get("library", imp.get("dll", imp.get("libname", "unknown"))) for imp in valid_imports
    ]
    stats["total_imports"] = len(valid_imports)
    stats["category_distribution"] = dict(Counter(categories))
    stats["risk_distribution"] = dict(Counter(risks))
    stats["library_distribution"] = dict(Counter(libraries))
    stats["unique_libraries"] = len(set(libraries))
    stats["suspicious_patterns"] = find_suspicious_patterns(valid_imports)
    return stats


def detect_api_obfuscation(imports: list[dict[str, Any]]) -> dict[str, Any]:
    indicators = _obfuscation_indicators(imports)
    return {
        "detected": len(indicators) > 0,
        "indicators": indicators,
        "score": min(len(indicators) * 20, 100),
    }


def _obfuscation_indicators(imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    indicators = []
    for type_name, description, count, include_zero in (
        (
            "dynamic_loading",
            "GetProcAddress usage detected - possible dynamic API loading",
            sum(1 for imp in imports if "GetProcAddress" in imp.get("name", "")),
            False,
        ),
        (
            "dynamic_library_loading",
            "LoadLibrary usage detected - possible dynamic library loading",
            sum(1 for imp in imports if "LoadLibrary" in imp.get("name", "")),
            False,
        ),
        (
            "few_imports",
            f"Very few imports ({len(imports)}) - possible static linking or packing",
            len(imports),
            len(imports) < 10,
        ),
        (
            "ordinal_imports",
            "Ordinal-only imports detected - possible obfuscation",
            sum(1 for imp in imports if not imp.get("name") and imp.get("ordinal", 0) > 0),
            False,
        ),
    ):
        if count > 0 or include_zero:
            indicators.append({"type": type_name, "description": description, "count": count})
    return indicators


def analyze_dll_dependencies(dlls: list[str]) -> dict[str, Any]:
    if not dlls:
        return {"common_dlls": [], "suspicious_dlls": [], "analysis": {}}

    common_found = [dll for dll in dlls if dll.lower() in COMMON_SYSTEM_DLLS]
    suspicious_found = [dll for dll in dlls if dll.lower() in SUSPICIOUS_DLLS]
    analysis = {
        "total_dlls": len(dlls),
        "common_ratio": len(common_found) / len(dlls) if dlls else 0,
        "suspicious_ratio": len(suspicious_found) / len(dlls) if dlls else 0,
        "unique_dlls": len({dll.lower() for dll in dlls}),
    }
    return {
        "common_dlls": common_found,
        "suspicious_dlls": suspicious_found,
        "analysis": analysis,
        "all_dlls": dlls,
    }


def detect_import_anomalies(imports: list[dict[str, Any]]) -> dict[str, Any]:
    anomalies: list[dict[str, Any]] = []
    if not imports:
        anomalies.append(
            {
                "type": "no_imports",
                "description": "No imports found - possible packing or static linking",
                "severity": "HIGH",
            }
        )
        return {"anomalies": anomalies, "count": len(anomalies)}

    duplicates = _duplicate_imports(imports)
    if duplicates:
        anomalies.append(
            {
                "type": "duplicate_imports",
                "description": f"Duplicate imports found: {', '.join(duplicates[:5])}",
                "severity": "MEDIUM",
                "count": len(duplicates),
            }
        )
    unusual_dlls = _unusual_dlls(imports)
    if len(unusual_dlls) > 5:
        anomalies.append(
            {
                "type": "many_unusual_dlls",
                "description": f"Many unusual DLLs: {len(unusual_dlls)} found",
                "severity": "MEDIUM",
                "dlls": unusual_dlls[:10],
            }
        )
    if len(imports) > 500:
        anomalies.append(
            {
                "type": "excessive_imports",
                "description": f"Excessive number of imports: {len(imports)}",
                "severity": "MEDIUM",
            }
        )
    return {"anomalies": anomalies, "count": len(anomalies)}


def _duplicate_imports(imports: list[Any]) -> list[str]:
    import_keys = []
    for imp in imports:
        if not isinstance(imp, dict):
            continue
        name = imp.get("name", "")
        if not name:
            continue
        library = imp.get("library", imp.get("dll", ""))
        import_keys.append(f"{library}!{name}" if library else name)
    return [name for name, count in Counter(import_keys).items() if count > 1]


def _unusual_dlls(imports: list[dict[str, Any]]) -> list[str]:
    unusual_dlls: list[str] = []
    for imp in imports:
        dll = imp.get("library", imp.get("dll", "")).lower()
        if (
            dll
            and dll not in unusual_dlls
            and not any(
                common in dll for common in ["kernel32", "user32", "advapi32", "ntdll", "msvcrt"]
            )
        ):
            unusual_dlls.append(dll)
    return unusual_dlls
