#!/usr/bin/env python3
"""Packer detection module."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast

from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..infrastructure.logging import get_logger
from .packer_helpers import (
    analyze_entropy,
    analyze_sections,
    count_imports,
    find_packer_signature,
    find_packer_string,
    overlay_info,
)
from .search_helpers import search_hex, search_text

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Evidence accumulator — single responsibility: scoring packing evidence
# ---------------------------------------------------------------------------


@dataclass
class PackerEvidenceScorer:
    """Accumulate evidence from multiple detection techniques and produce a verdict.

    Each ``add_*`` method contributes a weighted score and an optional human-
    readable reason.  Call ``verdict()`` once all evidence has been added.
    """

    _score: int = field(default=0, init=False)
    _reasons: list[str] = field(default_factory=list, init=False)
    _packer_type: str | None = field(default=None, init=False)
    _entropy_results: dict[str, Any] = field(default_factory=dict, init=False)
    _section_results: dict[str, Any] = field(default_factory=dict, init=False)

    def add_signature(self, signature: dict[str, str] | None) -> None:
        """Register a packer-signature hit (40 points)."""
        if signature:
            self._score += 40
            self._reasons.append(f"Packer signature: {signature['type']}")
            self._packer_type = signature["type"]

    def add_entropy_results(self, entropy_results: dict[str, Any]) -> None:
        """Register high-entropy sections (up to 30 points)."""
        self._entropy_results = entropy_results
        high_entropy_count = entropy_results.get("summary", {}).get("high_entropy_sections", 0)
        if high_entropy_count > 0:
            self._score += min(high_entropy_count * 15, 30)
            self._reasons.append(f"{high_entropy_count} high entropy sections (>7.0)")

    def add_section_results(self, section_results: dict[str, Any]) -> None:
        """Register suspicious-section findings (up to 20 points)."""
        self._section_results = section_results
        suspicious = len(section_results.get("suspicious_sections", []))
        if suspicious > 0:
            self._score += min(suspicious * 10, 20)
            self._reasons.append(f"{suspicious} suspicious sections")

    def add_import_count(self, import_count: int) -> None:
        """Register low import count as packing indicator (10 points)."""
        if import_count < 10:
            self._score += 10
            self._reasons.append(f"Few imports ({import_count})")

    def verdict(self) -> dict[str, Any]:
        """Return the final packed/unpacked determination with all supporting data."""
        is_packed = self._score >= 50
        confidence = min(self._score / 100.0, 0.95) if is_packed else self._score / 100.0
        indicators = self._reasons if self._reasons else ["No packing indicators found"]
        packer_type = (
            self._packer_type if is_packed and not self._packer_type else self._packer_type
        )
        if is_packed and not packer_type:
            packer_type = "Unknown (heuristic)"
        return {
            "is_packed": is_packed,
            "packer_type": packer_type,
            "confidence": confidence,
            "indicators": indicators,
            "entropy_analysis": self._entropy_results,
            "section_analysis": self._section_results,
        }


# ---------------------------------------------------------------------------
# Detector — single responsibility: data retrieval + orchestration
# ---------------------------------------------------------------------------


class PackerDetector(CommandHelperMixin):
    """Detect packers by coordinating signature, entropy, section, and import checks."""

    def __init__(self, adapter: Any, config: Any | None = None) -> None:
        self.adapter = adapter
        if config is None:
            raise ValueError("config must be provided")
        self.config = config
        self.entropy_threshold = config.typed_config.packer.entropy_threshold

        self.packer_signatures: dict[str, list[bytes]] = {
            "UPX": [b"UPX!", b"$Info: This file is packed with the UPX", b"UPX0", b"UPX1", b"UPX2"],
            "ASPack": [b"aPLib", b"ASPack", b".aspack"],
            "PECompact": [b"PECompact", b"pec1", b"pec2"],
            "Themida": [b"Themida", b"WinLicense", b".themida"],
            "VMProtect": [b"VMProtect", b".vmp0", b".vmp1"],
            "Armadillo": [b"Armadillo", b"Silicon Realms Toolworks"],
            "FSG": [b"FSG!", b"FSG v"],
            "MEW": [b"MEW ", b"MEW11"],
            "Petite": [b"Petite", b".petite"],
            "teLock": [b"teLock", b".teLock"],
            "Molebox": [b"MoleBox", b".molebox"],
            "MPRESS": [b"MPRESS", b".MPRESS"],
        }

    def analyze(self) -> dict[str, Any]:
        """Unified entry point for pipeline dispatch."""
        return self.detect()

    def detect(self) -> dict[str, Any]:
        """Coordinate all detection techniques and return a unified packing verdict."""
        scorer = PackerEvidenceScorer()
        scorer.add_signature(self._check_packer_signatures())
        scorer.add_entropy_results(self._analyze_entropy())
        scorer.add_section_results(self._analyze_sections())
        scorer.add_import_count(self._count_imports())
        return scorer.verdict()

    def _check_packer_signatures(self) -> dict[str, str] | None:
        """Check for known packer signatures in hex patterns and strings."""
        return self._safe_call(
            lambda: (
                find_packer_signature(self._search_hex, self.packer_signatures)
                or find_packer_string(self._get_strings(), self.packer_signatures)
            ),
            default=None,
            error_msg="Error checking packer signatures",
        )

    def _analyze_entropy(self) -> dict[str, Any]:
        """Analyze entropy of file sections."""
        return self._safe_call(
            lambda: analyze_entropy(self._get_sections(), self._read_bytes, self.entropy_threshold),
            default={},
            error_msg="Error analyzing entropy",
        )

    def _count_imports(self) -> int:
        """Count number of imports."""
        return self._safe_call(
            lambda: count_imports(self._get_imports()),
            default=0,
            error_msg="Error counting imports",
        )

    def _analyze_sections(self) -> dict[str, Any]:
        """Analyze section characteristics for packer indicators."""
        return self._safe_call(
            lambda: analyze_sections(self._get_sections()),
            default={
                "suspicious_sections": [],
                "section_count": 0,
                "executable_sections": 0,
                "writable_executable": 0,
            },
            error_msg="Error analyzing sections",
        )

    def _calculate_heuristic_score(self, entropy_results: dict, section_results: dict) -> float:
        """Calculate heuristic score for packer detection."""
        score = 0.0

        try:
            if "summary" in entropy_results:
                ratio = entropy_results["summary"].get("high_entropy_ratio", 0)
                score += ratio * 0.4

            suspicious_count = len(section_results.get("suspicious_sections", []))
            total_sections = section_results.get("section_count", 1)
            if suspicious_count > 0:
                score += min(suspicious_count / total_sections, 1.0) * 0.3

            wx_sections = section_results.get("writable_executable", 0)
            if wx_sections > 0:
                score += 0.3

            section_count = section_results.get("section_count", 0)
            if section_count <= 3:
                score += 0.2

        except Exception as e:
            logger.error("Error calculating heuristic score: %s", e)

        return min(score, 1.0)

    def get_overlay_info(self) -> dict[str, Any]:
        """Check for overlay data (common in packed files)."""
        return self._safe_call(
            lambda: overlay_info(self._get_file_info(), self._get_sections()),
            default={},
            error_msg="Error getting overlay info",
        )

    # -- data-access helpers (adapter-first, r2 fallback) --------------------

    def _get_imports(self) -> list[dict[str, Any]]:
        return cast(list[dict[str, Any]], self._get_via_adapter("get_imports", "iij"))

    def _get_sections(self) -> list[dict[str, Any]]:
        return cast(list[dict[str, Any]], self._get_via_adapter("get_sections", "iSj"))

    def _get_strings(self) -> list[dict[str, Any]]:
        return cast(list[dict[str, Any]], self._get_via_adapter("get_strings", "izj"))

    def _get_file_info(self) -> dict[str, Any]:
        return cast(dict[str, Any], self._get_via_adapter("get_file_info", "ij", as_dict=True))

    def _search_text(self, pattern: str) -> str:
        return search_text(self.adapter, pattern)

    def _search_hex(self, pattern: str) -> str:
        return search_hex(self.adapter, pattern)

    def _read_bytes(self, addr: int, size: int) -> bytes:
        if self.adapter is not None and hasattr(self.adapter, "read_bytes"):
            return cast(bytes, self.adapter.read_bytes(addr, size))
        hex_data = self._cmd(f"p8 {size} @ {addr}")
        return bytes.fromhex(hex_data) if hex_data else b""
