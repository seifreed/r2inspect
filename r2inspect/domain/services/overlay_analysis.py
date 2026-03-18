"""Pure overlay analysis helpers."""

from __future__ import annotations

import math
from typing import Any

INSTALLER_SIGNATURES: tuple[dict[str, Any], ...] = (
    {
        "name": "NSIS",
        "pattern": [0xEF, 0xBE, 0xAD, 0xDE, 0x4E, 0x75, 0x6C, 0x6C, 0x73, 0x6F, 0x66, 0x74],
    },
    {"name": "Inno Setup", "pattern": [0x49, 0x6E, 0x6E, 0x6F, 0x20, 0x53, 0x65, 0x74, 0x75, 0x70]},
    {"name": "WinRAR SFX", "pattern": [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]},
    {"name": "7-Zip SFX", "pattern": [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]},
    {"name": "AutoIt", "pattern": [0x41, 0x55, 0x33, 0x21, 0xEA, 0x06]},
    {"name": "MSI", "pattern": [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]},
)

FILE_SIGNATURES: tuple[dict[str, Any], ...] = (
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
    {"name": "XML", "magic": [0x3C, 0x3F, 0x78, 0x6D, 0x6C], "extension": "xml"},
    {"name": "MZ-DOS", "magic": [0x4D, 0x5A], "extension": "exe"},
    {"name": "ELF", "magic": [0x7F, 0x45, 0x4C, 0x46], "extension": "elf"},
    {"name": "CAB", "magic": [0x4D, 0x53, 0x43, 0x46], "extension": "cab"},
    {"name": "RTF", "magic": [0x7B, 0x5C, 0x72, 0x74, 0x66], "extension": "rtf"},
)

SUSPICIOUS_OVERLAY_STRINGS: tuple[str, ...] = (
    "cmd.exe",
    "powershell",
    "WScript.Shell",
    "HKEY_",
    "\\System32\\",
    "\\Windows\\",
    "CreateProcess",
    "VirtualAlloc",
    "WriteProcessMemory",
)


def calculate_overlay_entropy(data: list[int]) -> float:
    if not data:
        return 0.0
    data_length = len(data)
    entropy = 0.0
    for byte_value in set(data):
        probability = data.count(byte_value) / data_length
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def has_pattern(data: list[int], pattern: list[int]) -> bool:
    pattern_len = len(pattern)
    data_len = len(data)
    for index in range(data_len - pattern_len + 1):
        if data[index : index + pattern_len] == pattern:
            return True
    return False


def find_all_patterns(data: list[int], pattern: list[int]) -> list[int]:
    positions: list[int] = []
    pattern_len = len(pattern)
    data_len = len(data)
    for index in range(data_len - pattern_len + 1):
        if data[index : index + pattern_len] == pattern:
            positions.append(index)
    return positions


def looks_encrypted(data: list[int]) -> bool:
    if len(data) < 256:
        return False
    entropy = calculate_overlay_entropy(data[:256])
    if entropy > 7.5:
        return True
    return len(set(data[:256])) > 240


def detect_overlay_patterns(data: list[int]) -> list[dict[str, Any]]:
    patterns: list[dict[str, Any]] = []
    for signature in INSTALLER_SIGNATURES:
        if has_pattern(data, signature["pattern"]):
            patterns.append({"type": "installer", "name": signature["name"], "confidence": "high"})
    if looks_encrypted(data):
        patterns.append({"type": "encrypted", "name": "High entropy data", "confidence": "medium"})
    if has_pattern(data, [0x3C, 0x3F, 0x78, 0x6D, 0x6C]):
        patterns.append({"type": "config", "name": "XML data", "confidence": "high"})
    if has_pattern(data, [0x7B, 0x22]) or has_pattern(data, [0x5B, 0x7B]):
        patterns.append({"type": "config", "name": "JSON data", "confidence": "medium"})
    if has_pattern(data, [0x30, 0x82]) or has_pattern(data, [0x30, 0x80]):
        patterns.append(
            {
                "type": "signature",
                "name": "ASN.1 structure (possible certificate)",
                "confidence": "medium",
            }
        )
    return patterns


def determine_overlay_type(patterns: list[dict[str, Any]], data: list[int]) -> str:
    if not patterns:
        entropy = calculate_overlay_entropy(data[:1024])
        if entropy > 7.5:
            return "encrypted/compressed"
        if entropy < 3.0:
            return "padding"
        return "data"
    for pattern in patterns:
        if pattern["type"] == "installer":
            return f"installer ({pattern['name']})"
    type_counts: dict[str, int] = {}
    for pattern in patterns:
        pattern_type = pattern["type"]
        type_counts[pattern_type] = type_counts.get(pattern_type, 0) + 1
    if type_counts:
        return max(type_counts, key=lambda k: type_counts[k])
    return "unknown"


def detect_embedded_files(data: list[int]) -> list[dict[str, Any]]:
    signatures: list[dict[str, Any]] = []
    for signature in FILE_SIGNATURES:
        for position in find_all_patterns(data, signature["magic"]):
            signatures.append(
                {
                    "type": signature["name"],
                    "offset": position,
                    "extension": signature["extension"],
                    "magic": "".join(f"{byte:02X}" for byte in signature["magic"]),
                }
            )
    return signatures


def _indicator(indicator: str, details: str, severity: str) -> dict[str, str]:
    return {
        "indicator": indicator,
        "details": details,
        "severity": severity,
    }


def _matching_suspicious_strings(strings: list[str]) -> list[str]:
    matches: list[str] = []
    for string in strings:
        lowered = string.lower()
        if any(suspicious.lower() in lowered for suspicious in SUSPICIOUS_OVERLAY_STRINGS):
            matches.append(string)
    return matches


def build_overlay_suspicious_indicators(result: dict[str, Any]) -> list[dict[str, Any]]:
    suspicious: list[dict[str, Any]] = []
    if result["overlay_size"] > 1024 * 1024:
        suspicious.append(
            _indicator("Large overlay", f"Overlay size: {result['overlay_size']} bytes", "medium")
        )
    if result["overlay_entropy"] > 7.5:
        suspicious.append(
            _indicator("High entropy", f"Entropy: {result['overlay_entropy']}", "high")
        )
    for embedded in result.get("embedded_files", []):
        if embedded.get("type") in {"PE", "ELF"}:
            suspicious.append(
                _indicator(
                    "Embedded executable",
                    f"{embedded['type']} at offset {embedded['offset']}",
                    "high",
                )
            )
    for pattern in result.get("patterns_found", []):
        if pattern.get("name") == "AutoIt":
            suspicious.append(
                _indicator("AutoIt script", "AutoIt compiled script detected", "medium")
            )
    found_suspicious = _matching_suspicious_strings(result.get("extracted_strings", []))
    if found_suspicious:
        suspicious.append(
            _indicator("Suspicious strings", f"Found: {', '.join(found_suspicious[:5])}", "medium")
        )
    return suspicious
