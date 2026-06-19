"""Build typed AnalysisResult from raw pipeline dict output."""

from __future__ import annotations

from datetime import UTC, datetime
from collections.abc import Iterable
from typing import Any

from ..schemas.results_models import AnalysisResult
from .result_mapper_builders import (
    build_anti_analysis,
    build_crypto_result,
    build_export_info,
    build_file_info,
    build_function_info,
    build_hashing_result,
    build_import_info,
    build_indicator,
    build_packer_result,
    build_section_info,
    build_security_features,
    build_yara_match,
)


def _build_list(raw_list: Any, builder: Any) -> list[Any]:
    """Safely build a typed list from raw data."""
    if not raw_list:
        return []
    if isinstance(raw_list, list):
        items = raw_list
    elif isinstance(raw_list, (dict, str, bytes)) or not isinstance(raw_list, Iterable):
        return []
    else:
        items = list(raw_list)
    result = []
    for item in items:
        if isinstance(item, dict):
            result.append(builder(item))
        else:
            # Already a typed object or a primitive -- keep as-is
            result.append(item)
    return result


def build_analysis_result(raw: dict[str, Any]) -> AnalysisResult:
    """Convert raw pipeline dict to typed AnalysisResult.

    Extracts known keys into typed fields. Unknown keys are preserved
    in the underlying dict via ``to_dict()`` round-trip, but the typed
    wrapper provides safe attribute access with defaults.
    """
    # Handle already-typed results (idempotent call)
    if isinstance(raw, AnalysisResult):
        return raw

    return AnalysisResult(
        file_info=build_file_info(raw.get("file_info")),
        hashing=build_hashing_result(raw.get("hashing")),
        security=build_security_features(raw.get("security")),
        imports=_build_list(raw.get("imports"), build_import_info),
        exports=_build_list(raw.get("exports"), build_export_info),
        sections=_build_list(raw.get("sections"), build_section_info),
        strings=raw.get("strings", []),
        yara_matches=_build_list(raw.get("yara_matches", raw.get("yara")), build_yara_match),
        functions=_build_list(raw.get("functions"), build_function_info),
        anti_analysis=build_anti_analysis(raw.get("anti_analysis")),
        packer=build_packer_result(raw.get("packer")),
        crypto=build_crypto_result(raw.get("crypto")),
        indicators=_build_list(raw.get("indicators"), build_indicator),
        error=raw.get("error"),
        timestamp=(
            raw.get("timestamp", datetime.now(UTC))
            if not isinstance(raw.get("timestamp"), str)
            else datetime.fromisoformat(raw["timestamp"])
        ),
        execution_time=raw.get("execution_time", 0.0),
        _raw=raw,
    )
