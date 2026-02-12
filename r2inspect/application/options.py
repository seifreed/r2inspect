"""Application-level option builders."""

from __future__ import annotations

from typing import Any


def build_analysis_options(yara: str | None, sanitized_xor: str | None) -> dict[str, Any]:
    """Build analysis options with all modules enabled by default."""
    return {
        "detect_packer": True,
        "detect_crypto": True,
        "detect_av": True,
        "full_analysis": True,
        "custom_yara": yara,
        "xor_search": sanitized_xor,
    }
