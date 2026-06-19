"""Import anomaly and dependency helpers."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
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


def _coerce_import_list(imports: Any) -> list[dict[str, Any]]:
    if isinstance(imports, list):
        source = imports
    elif isinstance(imports, (dict, str, bytes)) or not isinstance(imports, Iterable):
        return []
    else:
        source = list(imports)
    return [imp for imp in source if isinstance(imp, dict)]


def analyze_dll_dependencies(dlls: list[str]) -> dict[str, Any]:
    if isinstance(dlls, list):
        source = dlls
    elif isinstance(dlls, (dict, str, bytes)) or not isinstance(dlls, Iterable):
        return {"common_dlls": [], "suspicious_dlls": [], "analysis": {}}
    else:
        source = list(dlls)
    if not source:
        return {"common_dlls": [], "suspicious_dlls": [], "analysis": {}}

    valid_dlls = [dll for dll in source if isinstance(dll, str)]
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


def _duplicate_imports(imports: list[Any]) -> list[str]:
    import_keys = []
    for imp in imports:
        if not isinstance(imp, dict):
            continue
        name = imp.get("name", "")
        if isinstance(name, bytes):
            name = name.decode(errors="ignore")
        if not isinstance(name, str) or not name:
            continue
        library = imp.get("library", imp.get("dll", ""))
        if isinstance(library, bytes):
            library = library.decode(errors="ignore")
        if isinstance(library, str):
            library = library.lower()
        import_keys.append(f"{library}!{name}" if library else name)
    return [name for name, count in Counter(import_keys).items() if count > 1]


def _unusual_dlls(imports: list[dict[str, Any]]) -> list[str]:
    unusual_dlls: list[str] = []
    for imp in imports:
        if not isinstance(imp, dict):
            continue
        dll_value = imp.get("library", imp.get("dll", ""))
        if isinstance(dll_value, bytes):
            dll_value = dll_value.decode(errors="ignore")
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
    valid_imports = _coerce_import_list(imports)
    if not valid_imports:
        return _anomaly_result([_no_imports_anomaly()])

    imports = valid_imports
    if not imports:
        return _anomaly_result([_no_imports_anomaly()])

    anomalies: list[dict[str, Any]] = []
    _append_duplicate_imports(anomalies, imports)
    _append_unusual_dlls(anomalies, imports)
    _append_excessive_imports(anomalies, imports)
    return _anomaly_result(anomalies)
