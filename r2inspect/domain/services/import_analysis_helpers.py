"""Pure helper logic for import-table analysis."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable
from typing import Any

from ..formats.import_analysis import NETWORK_CATEGORY
from .import_analysis_anomalies import (
    COMMON_SYSTEM_DLLS,
    SUSPICIOUS_DLLS,
    analyze_dll_dependencies,
    detect_import_anomalies,
)


def _text_value(value: Any, default: str) -> str:
    if isinstance(value, (bytes, bytearray)):
        value = value.decode(errors="ignore")
    return value if isinstance(value, str) and value else default


def _library_value(imp: dict[str, Any]) -> str:
    for key in ("library", "dll", "libname"):
        value = imp.get(key)
        if isinstance(value, bytes):
            value = value.decode(errors="ignore")
        if isinstance(value, str) and value:
            return value.lower()
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


def _coerce_import_list(imports: Any) -> list[dict[str, Any]]:
    if isinstance(imports, list):
        source = imports
    elif isinstance(imports, (dict, str, bytes)) or not isinstance(imports, Iterable):
        return []
    else:
        source = list(imports)
    return [imp for imp in source if isinstance(imp, dict)]


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


def find_suspicious_patterns(imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    valid_imports = _coerce_import_list(imports)
    if not valid_imports:
        return []
    patterns: list[dict[str, Any]] = []
    import_names = [_text_value(imp.get("name"), "") for imp in valid_imports]
    categories = [_text_value(imp.get("category"), "").strip().lower() for imp in valid_imports]
    _append_injection_patterns(patterns, import_names)
    _append_behavior_patterns(patterns, import_names, categories)
    return patterns


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

    valid_imports = _coerce_import_list(imports)
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


def detect_api_obfuscation(imports: list[dict[str, Any]]) -> dict[str, Any]:
    valid_imports = _coerce_import_list(imports)
    if not valid_imports:
        if isinstance(imports, list):
            return {
                "detected": True,
                "indicators": [
                    {
                        "type": "few_imports",
                        "description": "Very few imports (0) - possible static linking or packing",
                        "count": 0,
                    }
                ],
                "score": 20,
            }
        return {"detected": False, "indicators": [], "score": 0}
    indicators = _obfuscation_indicators(valid_imports)
    return {
        "detected": len(indicators) > 0,
        "indicators": indicators,
        "score": min(len(indicators) * 20, 100),
    }
