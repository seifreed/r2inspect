"""Result shaping helpers for overlay analysis."""

from __future__ import annotations

from typing import Any, TypedDict, cast


class OverlayResult(TypedDict):
    available: bool
    analyzer: str
    has_overlay: bool
    overlay_offset: int
    overlay_size: int
    overlay_entropy: float
    overlay_hashes: dict[str, str]
    patterns_found: list[dict[str, Any]]
    potential_type: str
    suspicious_indicators: list[dict[str, Any]]
    extracted_strings: list[str]
    file_size: int
    pe_end: int
    embedded_files: list[dict[str, Any]]
    error: str
    execution_time: float


def default_overlay_result(init_result_structure: Any) -> OverlayResult:
    return cast(
        OverlayResult,
        init_result_structure(
            {
                "available": True,
                "has_overlay": False,
                "overlay_offset": 0,
                "overlay_size": 0,
                "overlay_entropy": 0.0,
                "overlay_hashes": {},
                "patterns_found": [],
                "potential_type": "unknown",
                "suspicious_indicators": [],
                "extracted_strings": [],
                "file_size": 0,
                "pe_end": 0,
                "embedded_files": [],
                "error": "",
            }
        ),
    )


def populate_overlay_metadata(
    result: OverlayResult, file_size: int, pe_end: int, overlay_size: int
) -> None:
    result["has_overlay"] = True
    result["overlay_offset"] = pe_end
    result["overlay_size"] = overlay_size
    result["file_size"] = file_size
    result["pe_end"] = pe_end
