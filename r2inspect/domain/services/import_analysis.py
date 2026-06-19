"""Pure domain helpers for import-table analysis."""

from __future__ import annotations

from .import_analysis_helpers import (
    COMMON_SYSTEM_DLLS,
    NETWORK_CATEGORY,
    SUSPICIOUS_DLLS,
    analyze_dll_dependencies,
    build_import_statistics,
    detect_api_obfuscation,
    detect_import_anomalies,
    find_suspicious_patterns,
)

