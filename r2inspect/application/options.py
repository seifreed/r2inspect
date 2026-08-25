"""Application-level option builders."""

from __future__ import annotations

from typing import Any


def build_analysis_options(
    yara: str | None, sanitized_xor: str | None, profile: str = "standard"
) -> dict[str, Any]:
    """Build the effective options for a named analysis cost profile."""
    if profile not in {"fast", "standard", "deep", "forensic"}:
        raise ValueError(f"Unknown analysis profile: {profile}")
    deep = profile in {"deep", "forensic"}
    detect = profile != "fast"
    return {
        "profile": profile,
        "detect_packer": detect,
        "detect_crypto": detect,
        "detect_av": detect,
        "detect_anti_analysis": detect,
        "detect_compiler": detect,
        "detect_yara": detect,
        "analyze_functions": detect,
        "deep_analysis": deep,
        "detect_capa": deep,
        "detect_floss": deep,
        "full_analysis": detect,
        "forensic_evidence": profile == "forensic",
        "preserve_artifacts": profile == "forensic",
        "custom_yara": yara,
        "xor_search": sanitized_xor,
    }
