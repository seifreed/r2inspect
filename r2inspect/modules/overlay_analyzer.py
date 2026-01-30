# mypy: ignore-errors
"""
Overlay data analyzer module using radare2.
Analyzes data appended after the PE structure.
"""

import hashlib
import logging
import math
from typing import Any

from ..utils.r2_helpers import safe_cmd, safe_cmdj
from ..utils.r2_suppress import silent_cmdj

logger = logging.getLogger(__name__)


class OverlayAnalyzer:
    """Analyzes overlay data in PE files."""

    def __init__(self, r2):
        """
        Initialize the Overlay analyzer.

        Args:
            r2: Radare2 instance
        """
        self.r2 = r2

    def analyze(self) -> dict[str, Any]:
        """
        Analyze overlay data in the PE file.

        Returns:
            Dictionary containing overlay information
        """
        try:
            result = {
                "has_overlay": False,
                "overlay_offset": 0,
                "overlay_size": 0,
                "overlay_entropy": 0.0,
                "overlay_hashes": {},
                "patterns_found": [],
                "potential_type": "unknown",
                "suspicious_indicators": [],
                "extracted_strings": [],
            }

            # Get file size
            file_info = silent_cmdj(self.r2, "ij", {})
            if not file_info:
                return result

            # Handle different response formats from radare2
            if isinstance(file_info, dict):
                file_size = file_info.get("core", {}).get("size", 0)
            else:
                return result

            if file_size == 0:
                return result

            # Calculate where PE structure ends
            pe_end = self._calculate_pe_end()

            # Ensure pe_end and file_size are integers
            try:
                pe_end = int(pe_end) if pe_end else 0
                file_size = int(file_size) if file_size else 0
            except (ValueError, TypeError):
                return result

            if pe_end == 0 or pe_end >= file_size:
                return result

            # We have overlay data
            overlay_size = file_size - pe_end
            if overlay_size <= 0:
                return result

            result["has_overlay"] = True
            result["overlay_offset"] = pe_end
            result["overlay_size"] = overlay_size
            result["file_size"] = file_size
            result["pe_end"] = pe_end

            # Analyze overlay content
            self._analyze_overlay_content(result, pe_end, overlay_size)

            # Check for suspicious indicators
            self._check_suspicious_indicators(result)

            return result

        except Exception as e:
            logger.error(f"Error analyzing overlay data: {e}")
            return {"has_overlay": False, "error": str(e)}

    def _calculate_pe_end(self) -> int:
        """Calculate where the PE structure ends."""
        try:
            # Get all sections
            sections = silent_cmdj(self.r2, "iSj", [])
            if not isinstance(sections, list):
                sections = []
            if not sections:
                return 0

            # Find the last section's end
            max_end = 0
            for section in sections:
                if isinstance(section, dict):
                    # Calculate section end (raw offset + raw size)
                    section_end = section.get("paddr", 0) + section.get("size", 0)
                    if section_end > max_end:
                        max_end = section_end

            # Check if there's a certificate table that extends beyond sections
            data_dirs = silent_cmdj(self.r2, "iDj", [])
            if isinstance(data_dirs, list):
                for dd in data_dirs:
                    if isinstance(dd, dict) and dd.get("name") == "SECURITY":
                        cert_offset = dd.get("paddr", 0)
                        cert_size = dd.get("size", 0)
                        if cert_offset > 0 and cert_size > 0:
                            cert_end = cert_offset + cert_size
                            if cert_end > max_end:
                                max_end = cert_end

            return max_end

        except Exception as e:
            logger.error(f"Error calculating PE end: {e}")
            return 0

    def _analyze_overlay_content(self, result: dict[str, Any], offset: int, size: int):
        """Analyze the content of the overlay data."""
        try:
            # Read first part of overlay for analysis (limit to 64KB)
            read_size = min(size, 65536)
            overlay_data = silent_cmdj(self.r2, f"pxj {read_size} @ {offset}", [])

            if not overlay_data:
                return

            # Calculate entropy
            result["overlay_entropy"] = self._calculate_entropy(overlay_data)

            # Calculate hashes of overlay
            try:
                overlay_bytes = bytes(overlay_data[: min(len(overlay_data), read_size)])
                result["overlay_hashes"] = {
                    "md5": hashlib.md5(overlay_bytes, usedforsecurity=False).hexdigest(),
                    "sha1": hashlib.sha1(overlay_bytes, usedforsecurity=False).hexdigest(),
                    "sha256": hashlib.sha256(overlay_bytes).hexdigest(),
                }
            except Exception as e:
                logger.debug(f"Error calculating overlay hashes: {e}")
                result["overlay_hashes"] = {}

            # Check for known patterns
            patterns = self._check_patterns(overlay_data)
            result["patterns_found"] = patterns

            # Determine potential type based on patterns
            result["potential_type"] = self._determine_overlay_type(patterns, overlay_data)

            # Extract readable strings from overlay
            strings = self._extract_strings(overlay_data, min_length=6)
            result["extracted_strings"] = strings[:20]  # Limit to first 20 strings

            # Check for specific file signatures in overlay
            signatures = self._check_file_signatures(overlay_data)
            if signatures:
                result["embedded_files"] = signatures

        except Exception as e:
            logger.error(f"Error analyzing overlay content: {e}")

    def _calculate_entropy(self, data: list[int]) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        # Count byte frequencies
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)

        for count in freq.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    def _check_patterns(self, data: list[int]) -> list[dict[str, Any]]:
        """Check for known patterns in overlay data."""
        patterns = []

        # Check for installer patterns
        installer_sigs = [
            {
                "name": "NSIS",
                "pattern": [
                    0xEF,
                    0xBE,
                    0xAD,
                    0xDE,
                    0x4E,
                    0x75,
                    0x6C,
                    0x6C,
                    0x73,
                    0x6F,
                    0x66,
                    0x74,
                ],
            },
            {
                "name": "Inno Setup",
                "pattern": [0x49, 0x6E, 0x6E, 0x6F, 0x20, 0x53, 0x65, 0x74, 0x75, 0x70],
            },
            {"name": "WinRAR SFX", "pattern": [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]},
            {"name": "7-Zip SFX", "pattern": [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]},
            {"name": "AutoIt", "pattern": [0x41, 0x55, 0x33, 0x21, 0xEA, 0x06]},
            {
                "name": "MSI",
                "pattern": [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
            },
        ]

        for sig in installer_sigs:
            if self._find_pattern(data, sig["pattern"]):
                patterns.append({"type": "installer", "name": sig["name"], "confidence": "high"})

        # Check for encryption/compression patterns
        if self._looks_encrypted(data):
            patterns.append(
                {
                    "type": "encrypted",
                    "name": "High entropy data",
                    "confidence": "medium",
                }
            )

        # Check for configuration data patterns (XML, JSON, INI)
        if self._find_pattern(data, [0x3C, 0x3F, 0x78, 0x6D, 0x6C]):  # <?xml
            patterns.append({"type": "config", "name": "XML data", "confidence": "high"})

        if self._find_pattern(data, [0x7B, 0x22]) or self._find_pattern(
            data, [0x5B, 0x7B]
        ):  # {" or [{
            patterns.append({"type": "config", "name": "JSON data", "confidence": "medium"})

        # Check for digital signature patterns
        if self._find_pattern(data, [0x30, 0x82]) or self._find_pattern(
            data, [0x30, 0x80]
        ):  # ASN.1 sequence
            patterns.append(
                {
                    "type": "signature",
                    "name": "ASN.1 structure (possible certificate)",
                    "confidence": "medium",
                }
            )

        return patterns

    def _determine_overlay_type(self, patterns: list[dict], data: list[int]) -> str:
        """Determine the most likely type of overlay data."""
        if not patterns:
            # Check entropy to guess type
            entropy = self._calculate_entropy(data[:1024])
            if entropy > 7.5:
                return "encrypted/compressed"
            elif entropy < 3.0:
                return "padding"
            else:
                return "data"

        # Prioritize installer signatures
        for pattern in patterns:
            if pattern["type"] == "installer":
                return f"installer ({pattern['name']})"

        # Check other types
        type_counts = {}
        for pattern in patterns:
            ptype = pattern["type"]
            type_counts[ptype] = type_counts.get(ptype, 0) + 1

        if type_counts:
            return max(type_counts, key=type_counts.get)

        return "unknown"

    def _check_file_signatures(self, data: list[int]) -> list[dict[str, Any]]:
        """Check for embedded file signatures."""
        signatures = []

        file_sigs = [
            {"name": "PE", "magic": [0x4D, 0x5A], "extension": "exe/dll"},
            {"name": "ZIP", "magic": [0x50, 0x4B, 0x03, 0x04], "extension": "zip"},
            {"name": "RAR", "magic": [0x52, 0x61, 0x72, 0x21], "extension": "rar"},
            {"name": "7Z", "magic": [0x37, 0x7A, 0xBC, 0xAF], "extension": "7z"},
            {"name": "PDF", "magic": [0x25, 0x50, 0x44, 0x46], "extension": "pdf"},
            {"name": "PNG", "magic": [0x89, 0x50, 0x4E, 0x47], "extension": "png"},
            {"name": "JPEG", "magic": [0xFF, 0xD8, 0xFF], "extension": "jpg"},
            {"name": "GIF", "magic": [0x47, 0x49, 0x46, 0x38], "extension": "gif"},
            {"name": "RIFF", "magic": [0x52, 0x49, 0x46, 0x46], "extension": "wav/avi"},
            {"name": "OLE", "magic": [0xD0, 0xCF, 0x11, 0xE0], "extension": "doc/xls"},
            {
                "name": "XML",
                "magic": [0x3C, 0x3F, 0x78, 0x6D, 0x6C],
                "extension": "xml",
            },
            {"name": "MZ-DOS", "magic": [0x4D, 0x5A], "extension": "exe"},
            {"name": "ELF", "magic": [0x7F, 0x45, 0x4C, 0x46], "extension": "elf"},
            {"name": "CAB", "magic": [0x4D, 0x53, 0x43, 0x46], "extension": "cab"},
            {
                "name": "RTF",
                "magic": [0x7B, 0x5C, 0x72, 0x74, 0x66],
                "extension": "rtf",
            },
        ]

        for sig in file_sigs:
            positions = self._find_all_patterns(data, sig["magic"])
            for pos in positions:
                signatures.append(
                    {
                        "type": sig["name"],
                        "offset": pos,
                        "extension": sig["extension"],
                        "magic": "".join([f"{b:02X}" for b in sig["magic"]]),
                    }
                )

        return signatures

    def _looks_encrypted(self, data: list[int]) -> bool:
        """Check if data looks encrypted based on entropy and patterns."""
        if len(data) < 256:
            return False

        # Calculate entropy of first 256 bytes
        entropy = self._calculate_entropy(data[:256])

        # High entropy suggests encryption/compression
        if entropy > 7.5:
            return True

        # Check for repeating patterns (encrypted data usually doesn't have them)
        unique_bytes = len(set(data[:256]))
        return unique_bytes > 240  # Almost all bytes are unique

    def _extract_strings(self, data: list[int], min_length: int = 4) -> list[str]:
        """Extract readable strings from data."""
        strings = []
        current_string = []

        for byte in data:
            # Ensure byte is an integer
            try:
                byte_val = int(byte) if not isinstance(byte, int) else byte
            except (ValueError, TypeError):
                continue

            # Check if byte is printable ASCII
            if 0x20 <= byte_val <= 0x7E:
                current_string.append(chr(byte_val))
            else:
                if len(current_string) >= min_length:
                    strings.append("".join(current_string))
                current_string = []

        # Don't forget the last string
        if len(current_string) >= min_length:
            strings.append("".join(current_string))

        return strings[:50]  # Limit to first 50 strings

    def _find_pattern(self, data: list[int], pattern: list[int]) -> bool:
        """Find a byte pattern in data."""
        pattern_len = len(pattern)
        data_len = len(data)

        for i in range(data_len - pattern_len + 1):
            if data[i : i + pattern_len] == pattern:
                return True
        return False

    def _find_all_patterns(self, data: list[int], pattern: list[int]) -> list[int]:
        """Find all occurrences of a byte pattern in data."""
        positions = []
        pattern_len = len(pattern)
        data_len = len(data)

        for i in range(data_len - pattern_len + 1):
            if data[i : i + pattern_len] == pattern:
                positions.append(i)
        return positions

    def _check_suspicious_indicators(self, result: dict[str, Any]):
        """Check for suspicious indicators in overlay data."""
        suspicious = []

        self._check_large_overlay(result, suspicious)
        self._check_entropy(result, suspicious)
        self._check_embedded_executables(result, suspicious)
        self._check_autoit(result, suspicious)
        self._check_suspicious_strings(result, suspicious)

        result["suspicious_indicators"] = suspicious

    def _check_large_overlay(self, result: dict[str, Any], suspicious: list[dict[str, Any]]):
        if result["overlay_size"] > 1024 * 1024:
            suspicious.append(
                {
                    "indicator": "Large overlay",
                    "details": f"Overlay size: {result['overlay_size']} bytes",
                    "severity": "medium",
                }
            )

    def _check_entropy(self, result: dict[str, Any], suspicious: list[dict[str, Any]]):
        if result["overlay_entropy"] > 7.5:
            suspicious.append(
                {
                    "indicator": "High entropy",
                    "details": f"Entropy: {result['overlay_entropy']}",
                    "severity": "high",
                }
            )

    def _check_embedded_executables(self, result: dict[str, Any], suspicious: list[dict[str, Any]]):
        for embedded in result.get("embedded_files", []):
            if embedded.get("type") in ["PE", "ELF"]:
                suspicious.append(
                    {
                        "indicator": "Embedded executable",
                        "details": f"{embedded['type']} at offset {embedded['offset']}",
                        "severity": "high",
                    }
                )

    def _check_autoit(self, result: dict[str, Any], suspicious: list[dict[str, Any]]):
        for pattern in result.get("patterns_found", []):
            if pattern.get("name") == "AutoIt":
                suspicious.append(
                    {
                        "indicator": "AutoIt script",
                        "details": "AutoIt compiled script detected",
                        "severity": "medium",
                    }
                )

    def _check_suspicious_strings(self, result: dict[str, Any], suspicious: list[dict[str, Any]]):
        suspicious_strings = [
            "cmd.exe",
            "powershell",
            "WScript.Shell",
            "HKEY_",
            "\\System32\\",
            "\\Windows\\",
            "CreateProcess",
            "VirtualAlloc",
            "WriteProcessMemory",
        ]

        found_suspicious = []
        for string in result.get("extracted_strings", []):
            for sus_str in suspicious_strings:
                if sus_str.lower() in string.lower():
                    found_suspicious.append(string)
                    break

        if found_suspicious:
            suspicious.append(
                {
                    "indicator": "Suspicious strings",
                    "details": f"Found: {', '.join(found_suspicious[:5])}",
                    "severity": "medium",
                }
            )
