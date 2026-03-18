"""Result shaping helpers for import analysis."""

from __future__ import annotations

from typing import Any, cast


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
    return list(
        {
            (imp.get("library") or imp.get("libname", "")).lower()
            for imp in imports
            if imp.get("library") or imp.get("libname")
        }
    )


def populate_import_statistics(
    result: dict[str, Any],
    *,
    get_risk_level_fn: Any,
    count_suspicious_indicators_fn: Any,
) -> None:
    total_risk = (
        result["api_analysis"].get("risk_score", 0) * 0.4
        + result["obfuscation"].get("score", 0) * 0.3
        + (result["anomalies"].get("count", 0) * 10) * 0.2
        + (len(result["dll_analysis"].get("suspicious_dlls", [])) * 5) * 0.1
    )

    result["statistics"] = {
        "total_risk_score": min(total_risk, 100),
        "risk_level": get_risk_level_fn(total_risk),
        "suspicious_indicators": count_suspicious_indicators_fn(result),
    }
