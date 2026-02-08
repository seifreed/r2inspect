"""Overlay data analyzer."""

import hashlib
from typing import Any, TypedDict, cast

from ..utils.command_helpers import cmdj as cmdj_helper
from ..utils.logger import get_logger
from .domain_helpers import entropy_from_ints
from .string_extraction import extract_ascii_from_bytes

logger = get_logger(__name__)


class OverlayResult(TypedDict):
    available: bool
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


class OverlayAnalyzer:
    """Analyze overlay data in PE files."""

    def __init__(self, adapter: Any) -> None:
        """Initialize the analyzer."""
        self.adapter = adapter
        self.r2 = adapter

    def analyze(self) -> OverlayResult:
        """Analyze overlay data."""
        result = self._default_result()

        try:
            file_size = self._get_file_size()
            if not file_size:
                return result

            pe_end = self._get_valid_pe_end(file_size)
            if not pe_end:
                return result

            overlay_size = file_size - pe_end
            if overlay_size <= 0:
                return result

            self._populate_overlay_metadata(result, file_size, pe_end, overlay_size)
            self._analyze_overlay_content(result, pe_end, overlay_size)
            self._check_suspicious_indicators(result)
            return result

        except Exception as e:
            logger.error(f"Error analyzing overlay data: {e}")
            result = self._default_result()
            result["available"] = False
            result["has_overlay"] = False
            result["error"] = str(e)
            return result

    @staticmethod
    def _default_result() -> OverlayResult:
        return {
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

    def _get_file_size(self) -> int | None:
        file_info = self._cmdj("ij", {})
        if not isinstance(file_info, dict):
            return None
        file_size = file_info.get("core", {}).get("size", 0)
        if not file_size:
            return None
        try:
            return int(file_size)
        except (ValueError, TypeError):
            return None

    def _get_valid_pe_end(self, file_size: int) -> int | None:
        pe_end = self._calculate_pe_end()
        if not pe_end:
            return None
        try:
            pe_end_int = int(pe_end)
        except (ValueError, TypeError):
            return None
        if pe_end_int == 0 or pe_end_int >= file_size:
            return None
        return pe_end_int

    @staticmethod
    def _populate_overlay_metadata(
        result: OverlayResult, file_size: int, pe_end: int, overlay_size: int
    ) -> None:
        result["has_overlay"] = True
        result["overlay_offset"] = pe_end
        result["overlay_size"] = overlay_size
        result["file_size"] = file_size
        result["pe_end"] = pe_end

    def _calculate_pe_end(self) -> int:
        """Calculate where the PE structure ends."""
        try:
            sections = self._get_sections()
            if not sections:
                return 0
            max_end = self._get_max_section_end(sections)
            return self._extend_end_with_certificate(max_end)

        except Exception as e:
            logger.error(f"Error calculating PE end: {e}")
            return 0

    def _get_sections(self) -> list[dict[str, Any]]:
        sections = self._cmdj("iSj", [])
        if not isinstance(sections, list):
            return []
        return [section for section in sections if isinstance(section, dict)]

    @staticmethod
    def _get_max_section_end(sections: list[dict[str, Any]]) -> int:
        max_end = 0
        for section in sections:
            section_end = section.get("paddr", 0) + section.get("size", 0)
            if section_end > max_end:
                max_end = section_end
        return max_end

    def _extend_end_with_certificate(self, max_end: int) -> int:
        data_dirs = self._cmdj("iDj", [])
        if not isinstance(data_dirs, list):
            return max_end
        for dd in data_dirs:
            if not isinstance(dd, dict) or dd.get("name") != "SECURITY":
                continue
            cert_offset = dd.get("paddr", 0)
            cert_size = dd.get("size", 0)
            if cert_offset > 0 and cert_size > 0:
                max_end = max(max_end, cert_offset + cert_size)
        return max_end

    def _analyze_overlay_content(self, result: OverlayResult, offset: int, size: int) -> None:
        """Analyze the content of the overlay data."""
        try:
            # Read first part of overlay for analysis (limit to 64KB)
            read_size = min(size, 65536)
            overlay_data = self._cmdj(f"pxj {read_size} @ {offset}", [])

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
        """Calculate Shannon entropy."""
        return round(entropy_from_ints(data), 4)

    def _check_patterns(self, data: list[int]) -> list[dict[str, Any]]:
        """Check for known patterns in overlay data."""
        patterns: list[dict[str, Any]] = []

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
            pattern = cast(list[int], sig["pattern"])
            if self._find_pattern(data, pattern):
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

    def _determine_overlay_type(self, patterns: list[dict[str, Any]], data: list[int]) -> str:
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
        type_counts: dict[str, int] = {}
        for pattern in patterns:
            ptype = pattern["type"]
            type_counts[ptype] = type_counts.get(ptype, 0) + 1

        if type_counts:
            return max(type_counts, key=lambda key: type_counts[key])

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
            magic = cast(list[int], sig["magic"])
            positions = self._find_all_patterns(data, magic)
            for pos in positions:
                signatures.append(
                    {
                        "type": sig["name"],
                        "offset": pos,
                        "extension": sig["extension"],
                        "magic": "".join([f"{b:02X}" for b in magic]),
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

    def _cmdj(self, command: str, default: Any) -> Any:
        return cmdj_helper(self.adapter, self.r2, command, default)

    def _extract_strings(self, data: list[int], min_length: int = 4) -> list[str]:
        """Extract readable strings from data."""
        return extract_ascii_from_bytes(data, min_length=min_length, limit=50)

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

    def _check_suspicious_indicators(self, result: OverlayResult) -> None:
        """Check for suspicious indicators in overlay data."""
        suspicious: list[dict[str, Any]] = []

        self._check_large_overlay(result, suspicious)
        self._check_entropy(result, suspicious)
        self._check_embedded_executables(result, suspicious)
        self._check_autoit(result, suspicious)
        self._check_suspicious_strings(result, suspicious)

        result["suspicious_indicators"] = suspicious

    def _check_large_overlay(self, result: OverlayResult, suspicious: list[dict[str, Any]]) -> None:
        if result["overlay_size"] > 1024 * 1024:
            suspicious.append(
                {
                    "indicator": "Large overlay",
                    "details": f"Overlay size: {result['overlay_size']} bytes",
                    "severity": "medium",
                }
            )

    def _check_entropy(self, result: OverlayResult, suspicious: list[dict[str, Any]]) -> None:
        if result["overlay_entropy"] > 7.5:
            suspicious.append(
                {
                    "indicator": "High entropy",
                    "details": f"Entropy: {result['overlay_entropy']}",
                    "severity": "high",
                }
            )

    def _check_embedded_executables(
        self, result: OverlayResult, suspicious: list[dict[str, Any]]
    ) -> None:
        for embedded in result.get("embedded_files", []):
            if embedded.get("type") in ["PE", "ELF"]:
                suspicious.append(
                    {
                        "indicator": "Embedded executable",
                        "details": f"{embedded['type']} at offset {embedded['offset']}",
                        "severity": "high",
                    }
                )

    def _check_autoit(self, result: OverlayResult, suspicious: list[dict[str, Any]]) -> None:
        for pattern in result.get("patterns_found", []):
            if pattern.get("name") == "AutoIt":
                suspicious.append(
                    {
                        "indicator": "AutoIt script",
                        "details": "AutoIt compiled script detected",
                        "severity": "medium",
                    }
                )

    def _check_suspicious_strings(
        self, result: OverlayResult, suspicious: list[dict[str, Any]]
    ) -> None:
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
