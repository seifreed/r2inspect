#!/usr/bin/env python3
"""Packer detection module."""

from typing import Any, cast

from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..utils.logger import get_logger
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


class PackerDetector(CommandHelperMixin):
    """Packer detection using radare2 and entropy analysis"""

    def __init__(self, adapter: Any, config: Any | None = None) -> None:
        self.adapter = adapter
        self.r2 = adapter
        if config is None:
            raise ValueError("config must be provided")
        self.config = config
        self.entropy_threshold = config.typed_config.packer.entropy_threshold

        # Known packer signatures
        self.packer_signatures = {
            "UPX": [
                b"UPX!",
                b"$Info: This file is packed with the UPX",
                b"UPX0",
                b"UPX1",
                b"UPX2",
            ],
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

    def detect(self) -> dict[str, Any]:
        """Detect if file is packed"""
        packer_info: dict[str, Any] = {
            "is_packed": False,
            "packer_type": None,
            "confidence": 0.0,
            "indicators": [],
            "entropy_analysis": {},
            "section_analysis": {},
        }

        try:
            # Check for packer signatures
            signature_results = self._check_packer_signatures()

            # Analyze entropy
            entropy_results = self._analyze_entropy()
            packer_info["entropy_analysis"] = entropy_results

            # Check sections
            section_results = self._analyze_sections()
            packer_info["section_analysis"] = section_results

            # Enhanced packer detection with multiple evidence requirement
            evidence_score = 0
            evidence_reasons = []

            # Evidence 1: Signature found
            if signature_results:
                evidence_score += 40
                evidence_reasons.append(f"Packer signature: {signature_results['type']}")
                packer_info["packer_type"] = signature_results["type"]

            # Evidence 2: High entropy sections
            high_entropy_count = entropy_results.get("summary", {}).get("high_entropy_sections", 0)
            if high_entropy_count > 0:
                evidence_score += min(high_entropy_count * 15, 30)
                evidence_reasons.append(f"{high_entropy_count} high entropy sections (>7.0)")

            # Evidence 3: Suspicious section characteristics
            suspicious_sections = len(section_results.get("suspicious_sections", []))
            if suspicious_sections > 0:
                evidence_score += min(suspicious_sections * 10, 20)
                evidence_reasons.append(f"{suspicious_sections} suspicious sections")

            # Evidence 4: Lack of imports (common in packed files)
            import_count = self._count_imports()
            if import_count < 10:
                evidence_score += 10
                evidence_reasons.append(f"Few imports ({import_count})")

            # Determine if packed based on evidence
            if evidence_score >= 50:  # Require substantial evidence
                packer_info["is_packed"] = True
                packer_info["confidence"] = min(evidence_score / 100.0, 0.95)
                packer_info["indicators"] = evidence_reasons

                if not packer_info["packer_type"]:
                    packer_info["packer_type"] = "Unknown (heuristic)"
            else:
                packer_info["is_packed"] = False
                packer_info["confidence"] = evidence_score / 100.0
                packer_info["indicators"] = (
                    evidence_reasons if evidence_reasons else ["No packing indicators found"]
                )

        except Exception as e:
            logger.error(f"Error in packer detection: {e}")
            packer_info["error"] = str(e)

        return packer_info

    def _check_packer_signatures(self) -> dict[str, str] | None:
        """Check for known packer signatures"""

        try:
            signature = find_packer_signature(self._search_hex, self.packer_signatures)
            if signature:
                return signature

            packer_string = find_packer_string(self._get_strings(), self.packer_signatures)
            if packer_string:
                return packer_string

        except Exception as e:
            logger.error(f"Error checking packer signatures: {e}")

        return None

    def _analyze_entropy(self) -> dict[str, Any]:
        """Analyze entropy of file sections"""
        try:
            return analyze_entropy(self._get_sections(), self._read_bytes, self.entropy_threshold)

        except Exception as e:
            logger.error(f"Error analyzing entropy: {e}")

        return {}

    def _count_imports(self) -> int:
        """Count number of imports"""
        try:
            return count_imports(self._get_imports())
        except Exception as e:
            logger.debug(f"Error counting imports: {e}")
            return 0

    def _analyze_sections(self) -> dict[str, Any]:
        """Analyze section characteristics for packer indicators"""
        try:
            return analyze_sections(self._get_sections())

        except Exception as e:
            logger.error(f"Error analyzing sections: {e}")

        return {
            "suspicious_sections": [],
            "section_count": 0,
            "executable_sections": 0,
            "writable_executable": 0,
        }

    def _calculate_heuristic_score(self, entropy_results: dict, section_results: dict) -> float:
        """Calculate heuristic score for packer detection"""
        score = 0.0

        try:
            # Entropy score
            if "summary" in entropy_results:
                ratio = entropy_results["summary"].get("high_entropy_ratio", 0)
                score += ratio * 0.4  # 40% weight for entropy

            # Section analysis score
            suspicious_count = len(section_results.get("suspicious_sections", []))
            total_sections = section_results.get("section_count", 1)

            if suspicious_count > 0:
                score += min(suspicious_count / total_sections, 1.0) * 0.3  # 30% weight

            # Writable+executable sections
            wx_sections = section_results.get("writable_executable", 0)
            if wx_sections > 0:
                score += 0.3  # 30% weight for W+X sections

            # Low section count (typical of packed files)
            section_count = section_results.get("section_count", 0)
            if section_count <= 3:
                score += 0.2  # 20% weight for few sections

        except Exception as e:
            logger.error(f"Error calculating heuristic score: {e}")

        return min(score, 1.0)

    def get_overlay_info(self) -> dict[str, Any]:
        """Check for overlay data (common in packed files)"""
        try:
            # Get file info
            return overlay_info(self._get_file_info(), self._get_sections())

        except Exception as e:
            logger.error(f"Error getting overlay info: {e}")

        return {}

    def _get_imports(self) -> list[dict[str, Any]]:
        if self.adapter is not None and hasattr(self.adapter, "get_imports"):
            return cast(list[dict[str, Any]], self.adapter.get_imports())
        return self._cmd_list("iij")

    def _get_sections(self) -> list[dict[str, Any]]:
        if self.adapter is not None and hasattr(self.adapter, "get_sections"):
            return cast(list[dict[str, Any]], self.adapter.get_sections())
        return self._cmd_list("iSj")

    def _get_strings(self) -> list[dict[str, Any]]:
        if self.adapter is not None and hasattr(self.adapter, "get_strings"):
            return cast(list[dict[str, Any]], self.adapter.get_strings())
        return self._cmd_list("izj")

    def _search_text(self, pattern: str) -> str:
        return search_text(self.adapter, self.r2, pattern)

    def _search_hex(self, pattern: str) -> str:
        return search_hex(self.adapter, self.r2, pattern)

    def _get_file_info(self) -> dict[str, Any]:
        if self.adapter is not None and hasattr(self.adapter, "get_file_info"):
            return cast(dict[str, Any], self.adapter.get_file_info())
        return cast(dict[str, Any], self._cmdj("ij", {}))

    def _read_bytes(self, addr: int, size: int) -> bytes:
        if self.adapter is not None and hasattr(self.adapter, "read_bytes"):
            return cast(bytes, self.adapter.read_bytes(addr, size))
        hex_data = self._cmd(f"p8 {size} @ {addr}")
        return bytes.fromhex(hex_data) if hex_data else b""
