"""Result shaping helpers for import analysis."""

from __future__ import annotations

from typing import Any, cast

from ..abstractions.coercion_support import coerce_dict_list


def _coerce_string_list(raw: Any) -> list[str]:
    if isinstance(raw, list):
        source = raw
    elif isinstance(raw, (dict, str, bytes, bytearray)):
        return []
    else:
        try:
            source = list(raw)
        except TypeError:
            return []
    values: list[str] = []
    for item in source:
        if isinstance(item, (bytes, bytearray)):
            item = item.decode(errors="ignore")
        if isinstance(item, str) and item:
            values.append(item)
        elif isinstance(item, dict):
            value = item.get("name")
            if isinstance(value, bytes):
                value = value.decode(errors="ignore")
            if isinstance(value, str) and value:
                values.append(value)
    return values


def init_import_result(init_result_structure: Any) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        init_result_structure(
            {
                "total_imports": 0,
                "total_dlls": 0,
                "imports": [],
                "dlls": [],
                "statistics": {},
                "api_analysis": {},
                "obfuscation": {},
                "dll_analysis": {},
                "anomalies": {},
                "forwarding": {},
            }
        ),
    )


def collect_import_dlls(imports: list[dict[str, Any]]) -> list[str]:
    # Normalize DLL names to lowercase for case-insensitive deduplication (Windows)
    # Also check 'libname' field which some r2 versions use instead of 'library'
    dlls = set()
    for imp in coerce_dict_list(imports):
        dll = imp.get("library") or imp.get("libname")
        if isinstance(dll, (bytes, bytearray)):
            dll = dll.decode(errors="ignore")
        if isinstance(dll, str) and dll:
            dlls.add(dll.lower())
    return sorted(dlls)


def _coerce_number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def populate_import_statistics(
    result: dict[str, Any],
    *,
    get_risk_level_fn: Any,
    count_suspicious_indicators_fn: Any,
) -> None:
    if not isinstance(result, dict):
        return
    api_analysis = result.get("api_analysis")
    if not isinstance(api_analysis, dict):
        api_analysis = {}
    obfuscation = result.get("obfuscation")
    if not isinstance(obfuscation, dict):
        obfuscation = {}
    anomalies = result.get("anomalies")
    if not isinstance(anomalies, dict):
        anomalies = {}
    dll_analysis = result.get("dll_analysis")
    if not isinstance(dll_analysis, dict):
        dll_analysis = {}
    suspicious_dlls = dll_analysis.get("suspicious_dlls")
    if not isinstance(suspicious_dlls, list):
        suspicious_dlls = _coerce_string_list(suspicious_dlls)
    else:
        suspicious_dlls = _coerce_string_list(suspicious_dlls)

    total_risk = (
        _coerce_number(api_analysis.get("risk_score", 0)) * 0.4
        + _coerce_number(obfuscation.get("score", 0)) * 0.3
        + (_coerce_number(anomalies.get("count", 0)) * 10) * 0.2
        + (len(suspicious_dlls) * 5) * 0.1
    )

    result["statistics"] = {
        "total_risk_score": min(total_risk, 100),
        "risk_level": get_risk_level_fn(total_risk),
        "suspicious_indicators": count_suspicious_indicators_fn(result),
    }
