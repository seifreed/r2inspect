#!/usr/bin/env python3
# mypy: ignore-errors
"""
Packer Detection Module using r2pipe
"""

import math
from typing import Any

from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmdj

logger = get_logger(__name__)


class PackerDetector:
    """Packer detection using radare2 and entropy analysis"""

    def __init__(self, r2, config):
        self.r2 = r2
        self.config = config
        self.entropy_threshold = config.get("packer", "entropy_threshold", 7.0)

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
        packer_info = {
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
            signature = self._find_packer_signature()
            if signature:
                return signature

            packer_string = self._find_packer_string()
            if packer_string:
                return packer_string

        except Exception as e:
            logger.error(f"Error checking packer signatures: {e}")

        return None

    def _find_packer_signature(self) -> dict[str, str] | None:
        for packer_name, signatures in self.packer_signatures.items():
            for signature in signatures:
                if self._search_signature_hex(signature.hex()):
                    return {
                        "type": packer_name,
                        "signature": signature.decode("utf-8", errors="ignore"),
                    }
        return None

    def _search_signature_hex(self, hex_sig: str) -> bool:
        search_cmd = f"/x {hex_sig}"
        result = self.r2.cmd(search_cmd)
        return bool(result and result.strip())

    def _find_packer_string(self) -> dict[str, str] | None:
        strings_result = safe_cmdj(self.r2, "izj")
        if not strings_result:
            return None
        for string_info in strings_result:
            string_val = string_info.get("string", "").lower()
            for packer_name in self.packer_signatures:
                if packer_name.lower() in string_val:
                    return {"type": packer_name, "signature": string_val}
        return None

    def _analyze_entropy(self) -> dict[str, Any]:
        """Analyze entropy of file sections"""
        entropy_info = {}

        try:
            sections = safe_cmdj(self.r2, "iSj")

            if sections:
                high_entropy_sections = 0
                total_sections = len(sections)

                for section in sections:
                    section_name = str(section.get("name", "unknown"))
                    entropy = self._calculate_section_entropy(section)

                    entropy_info[section_name] = {
                        "entropy": entropy,
                        "size": section.get("size", 0),
                        "high_entropy": entropy > self.entropy_threshold,
                    }

                    if entropy > self.entropy_threshold:
                        high_entropy_sections += 1

                entropy_info["summary"] = {
                    "high_entropy_sections": high_entropy_sections,
                    "total_sections": total_sections,
                    "high_entropy_ratio": (
                        high_entropy_sections / total_sections if total_sections > 0 else 0
                    ),
                }

        except Exception as e:
            logger.error(f"Error analyzing entropy: {e}")

        return entropy_info

    def _calculate_section_entropy(self, section: dict[str, Any]) -> float:
        """Calculate Shannon entropy for a section"""
        try:
            vaddr = section.get("vaddr", 0)
            size = section.get("size", 0)

            if size == 0 or size > 10000000:  # Skip very large sections
                return 0.0

            # Read section data
            data_cmd = f"p8 {min(size, 65536)} @ {vaddr}"  # Limit to 64KB for performance
            hex_data = self.r2.cmd(data_cmd)

            if not hex_data or not hex_data.strip():
                return 0.0

            try:
                data = bytes.fromhex(hex_data.strip())
            except ValueError:
                return 0.0

            if len(data) == 0:
                return 0.0

            # Calculate byte frequencies
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1

            # Calculate Shannon entropy
            entropy = 0.0
            data_len = len(data)

            for count in byte_counts:
                if count > 0:
                    p = count / data_len
                    entropy -= p * math.log2(p)

            return entropy

        except Exception as e:
            logger.error(f"Error calculating section entropy: {e}")
            return 0.0

    def _count_imports(self) -> int:
        """Count number of imports"""
        try:
            imports = safe_cmdj(self.r2, "iij")
            return len(imports) if imports else 0
        except Exception as e:
            logger.debug(f"Error counting imports: {e}")
            return 0

    def _analyze_sections(self) -> dict[str, Any]:
        """Analyze section characteristics for packer indicators"""
        section_info = {
            "suspicious_sections": [],
            "section_count": 0,
            "executable_sections": 0,
            "writable_executable": 0,
        }

        try:
            sections = safe_cmdj(self.r2, "iSj")

            if sections:
                section_info["section_count"] = len(sections)

                for section in sections:
                    self._update_section_info(section_info, section)

        except Exception as e:
            logger.error(f"Error analyzing sections: {e}")

        return section_info

    def _update_section_info(self, section_info: dict[str, Any], section: dict[str, Any]) -> None:
        name = str(section.get("name", ""))
        flags = str(section.get("flags", ""))
        size = section.get("size", 0)

        if "x" in flags:
            section_info["executable_sections"] += 1
            if "w" in flags:
                section_info["writable_executable"] += 1
                section_info["suspicious_sections"].append(
                    {"name": name, "reason": "Writable and executable", "flags": flags}
                )

        if self._is_suspicious_section_name(name):
            section_info["suspicious_sections"].append(
                {"name": name, "reason": "Suspicious section name", "flags": flags}
            )

        if size < 100:
            section_info["suspicious_sections"].append(
                {"name": name, "reason": "Very small section", "size": size}
            )
        elif size > 10000000:
            section_info["suspicious_sections"].append(
                {"name": name, "reason": "Very large section", "size": size}
            )

    def _is_suspicious_section_name(self, name: str) -> bool:
        suspicious_names = [".upx", ".aspack", ".themida", ".vmp", ".packed"]
        return isinstance(name, str) and any(
            sus_name in name.lower() for sus_name in suspicious_names
        )

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
        overlay_info = {}

        try:
            # Get file info
            file_info = safe_cmdj(self.r2, "ij")

            if file_info and "bin" in file_info:
                bin_info = file_info["bin"]
                file_size = bin_info.get("size", 0)

                # Check if there's data after the last section
                sections = safe_cmdj(self.r2, "iSj")
                if sections:
                    last_section_end = 0
                    for section in sections:
                        section_end = section.get("vaddr", 0) + section.get("size", 0)
                        last_section_end = max(last_section_end, section_end)

                    overlay_size = file_size - last_section_end

                    overlay_info = {
                        "has_overlay": overlay_size > 0,
                        "overlay_size": overlay_size,
                        "overlay_ratio": overlay_size / file_size if file_size > 0 else 0,
                    }

        except Exception as e:
            logger.error(f"Error getting overlay info: {e}")

        return overlay_info
