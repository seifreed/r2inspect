#!/usr/bin/env python3
"""Pure domain helpers for import-table analysis."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
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


def _text_value(value: Any, default: str) -> str:
    return value if isinstance(value, str) and value else default


def _library_value(imp: dict[str, Any]) -> str:
    for key in ("library", "dll", "libname"):
        value = imp.get(key)
        if isinstance(value, str) and value:
            return value
    return "unknown"


def _count_matching_apis(import_names: list[str], apis: list[str]) -> int:
    lowered_apis = [api.lower() for api in apis if isinstance(api, str)]
    return sum(
        1
        for name in import_names
        if isinstance(name, str) and any(api in name.lower() for api in lowered_apis)
    )


def _pattern_entry(pattern: str, description: str, severity: str, count: int) -> dict[str, Any]:
    return {
        "pattern": pattern,
        "description": description,
        "severity": severity,
        "count": count,
    }


def find_suspicious_patterns(imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(imports, list):
        return []
    patterns: list[dict[str, Any]] = []
    valid_imports = [imp for imp in imports if isinstance(imp, dict)]
    import_names = [_text_value(imp.get("name"), "") for imp in valid_imports]
    categories = [_text_value(imp.get("category"), "").strip().lower() for imp in valid_imports]
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
            categories.count(NETWORK_CATEGORY.lower()) > 5,
            _pattern_entry(
                "Heavy Network Usage",
                f"Many network-related APIs ({categories.count(NETWORK_CATEGORY.lower())})",
                "Medium",
                categories.count(NETWORK_CATEGORY.lower()),
            ),
        ),
        (
            categories.count("anti-analysis") > 0,
            _pattern_entry(
                "Anti-Analysis",
                f"Anti-analysis APIs detected ({categories.count('anti-analysis')})",
                "High",
                categories.count("anti-analysis"),
            ),
        ),
        (
            categories.count("cryptography") > 3,
            _pattern_entry(
                "Heavy Cryptography",
                f"Many cryptographic APIs ({categories.count('cryptography')})",
                "Medium",
                categories.count("cryptography"),
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
    if not isinstance(imports, list) or not imports:
        return stats

    valid_imports = [imp for imp in imports if isinstance(imp, dict)]
    if not valid_imports:
        return stats
    categories = [_text_value(imp.get("category"), "unknown") for imp in valid_imports]
    risks = [_text_value(imp.get("risk_level"), "unknown") for imp in valid_imports]
    libraries = [_library_value(imp) for imp in valid_imports]
    stats["total_imports"] = len(valid_imports)
    stats["category_distribution"] = dict(Counter(categories))
    stats["risk_distribution"] = dict(Counter(risks))
    stats["library_distribution"] = dict(Counter(libraries))
    stats["unique_libraries"] = len(set(libraries))
    stats["suspicious_patterns"] = find_suspicious_patterns(valid_imports)
    return stats


def detect_api_obfuscation(imports: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(imports, list):
        return {"detected": False, "indicators": [], "score": 0}
    valid_imports = [imp for imp in imports if isinstance(imp, dict)]
    indicators = _obfuscation_indicators(valid_imports)
    return {
        "detected": len(indicators) > 0,
        "indicators": indicators,
        "score": min(len(indicators) * 20, 100),
    }


def _count_imports(
    imports: list[dict[str, Any]], predicate: Callable[[dict[str, Any]], bool]
) -> int:
    return sum(1 for imp in imports if predicate(imp))


def _obfuscation_indicators(imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates = (
        (
            "dynamic_loading",
            "GetProcAddress usage detected - possible dynamic API loading",
            _count_imports(
                imports,
                lambda imp: isinstance(imp.get("name"), str)
                and "GetProcAddress" in imp["name"],
            ),
            False,
        ),
        (
            "dynamic_library_loading",
            "LoadLibrary usage detected - possible dynamic library loading",
            _count_imports(
                imports,
                lambda imp: isinstance(imp.get("name"), str) and "LoadLibrary" in imp["name"],
            ),
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
            _count_imports(
                imports,
                lambda imp: not imp.get("name")
                and isinstance(imp.get("ordinal"), int)
                and imp["ordinal"] > 0,
            ),
            False,
        ),
    )
    indicators = []
    for type_name, description, count, include_zero in candidates:
        if count > 0 or include_zero:
            indicators.append({"type": type_name, "description": description, "count": count})
    return indicators


def analyze_dll_dependencies(dlls: list[str]) -> dict[str, Any]:
    if not isinstance(dlls, list) or not dlls:
        return {"common_dlls": [], "suspicious_dlls": [], "analysis": {}}

    valid_dlls = [dll for dll in dlls if isinstance(dll, str)]
    if not valid_dlls:
        return {"common_dlls": [], "suspicious_dlls": [], "analysis": {}}

    common_found = [dll for dll in valid_dlls if dll.lower() in COMMON_SYSTEM_DLLS]
    suspicious_found = [dll for dll in valid_dlls if dll.lower() in SUSPICIOUS_DLLS]
    analysis = {
        "total_dlls": len(valid_dlls),
        "common_ratio": len(common_found) / len(valid_dlls),
        "suspicious_ratio": len(suspicious_found) / len(valid_dlls),
        "unique_dlls": len({dll.lower() for dll in valid_dlls}),
    }
    return {
        "common_dlls": common_found,
        "suspicious_dlls": suspicious_found,
        "analysis": analysis,
        "all_dlls": valid_dlls,
    }


def _anomaly_result(anomalies: list[dict[str, Any]]) -> dict[str, Any]:
    return {"anomalies": anomalies, "count": len(anomalies)}


def _no_imports_anomaly() -> dict[str, str]:
    description = "No imports found - possible packing or static linking"
    return {"type": "no_imports", "description": description, "severity": "HIGH"}


def _append_duplicate_imports(anomalies: list[dict[str, Any]], imports: list[dict[str, Any]]) -> None:
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


def _append_unusual_dlls(anomalies: list[dict[str, Any]], imports: list[dict[str, Any]]) -> None:
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


def _append_excessive_imports(anomalies: list[dict[str, Any]], imports: list[dict[str, Any]]) -> None:
    if len(imports) > 500:
        anomalies.append(
            {
                "type": "excessive_imports",
                "description": f"Excessive number of imports: {len(imports)}",
                "severity": "MEDIUM",
            }
        )


def detect_import_anomalies(imports: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(imports, list) or not imports:
        return _anomaly_result([_no_imports_anomaly()])

    valid_imports = [imp for imp in imports if isinstance(imp, dict)]
    if not valid_imports:
        return _anomaly_result([_no_imports_anomaly()])

    anomalies: list[dict[str, Any]] = []
    _append_duplicate_imports(anomalies, valid_imports)
    _append_unusual_dlls(anomalies, valid_imports)
    _append_excessive_imports(anomalies, valid_imports)
    return _anomaly_result(anomalies)


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
        if not isinstance(imp, dict):
            continue
        dll_value = imp.get("library", imp.get("dll", ""))
        if not isinstance(dll_value, str):
            continue
        dll = dll_value.lower()
        if (
            dll
            and dll not in unusual_dlls
            and not any(
                common in dll for common in ["kernel32", "user32", "advapi32", "ntdll", "msvcrt"]
            )
        ):
            unusual_dlls.append(dll)
    return unusual_dlls
