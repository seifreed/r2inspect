#!/usr/bin/env python3
"""
Enhanced file type detection using precise magic bytes
"""

import struct
from pathlib import Path
from typing import Any, BinaryIO

from .logger import get_logger

logger = get_logger(__name__)


class MagicByteDetector:
    """Enhanced file type detection with precise magic byte patterns"""

    # Comprehensive magic byte patterns for executable formats
    MAGIC_PATTERNS: dict[str, dict[str, Any]] = {
        # PE (Portable Executable) - Windows
        "PE32": {
            "signatures": [
                (0, b"MZ"),  # DOS header
                # PE signature will be checked at offset specified in DOS header + 0x3C
            ],
            "pe_check": True,
            "description": "Windows PE32 Executable",
            "extensions": [".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv"],
        },
        # ELF (Executable and Linkable Format) - Linux/Unix
        "ELF32": {
            "signatures": [
                (0, b"\x7fELF\x01"),  # ELF32
            ],
            "description": "Linux ELF 32-bit Executable",
            "extensions": [".so", ".o", ".ko"],
        },
        "ELF64": {
            "signatures": [
                (0, b"\x7fELF\x02"),  # ELF64
            ],
            "description": "Linux ELF 64-bit Executable",
            "extensions": [".so", ".o", ".ko"],
        },
        # Mach-O (Mach Object) - macOS
        "MACHO32": {
            "signatures": [
                (0, b"\xfe\xed\xfa\xce"),  # Mach-O 32-bit big-endian
                (0, b"\xce\xfa\xed\xfe"),  # Mach-O 32-bit little-endian
            ],
            "description": "macOS Mach-O 32-bit Executable",
            "extensions": [".dylib", ".bundle", ".o"],
        },
        "MACHO64": {
            "signatures": [
                (0, b"\xfe\xed\xfa\xcf"),  # Mach-O 64-bit big-endian
                (0, b"\xcf\xfa\xed\xfe"),  # Mach-O 64-bit little-endian
            ],
            "description": "macOS Mach-O 64-bit Executable",
            "extensions": [".dylib", ".bundle", ".o"],
        },
        "MACHO_UNIVERSAL": {
            "signatures": [
                (0, b"\xca\xfe\xba\xbe"),  # Universal binary big-endian
                (0, b"\xbe\xba\xfe\xca"),  # Universal binary little-endian
            ],
            "description": "macOS Universal Binary",
            "extensions": [],
        },
        # Archive formats that may contain executables
        "ZIP": {
            "signatures": [
                (0, b"PK\x03\x04"),  # ZIP file
                (0, b"PK\x05\x06"),  # Empty ZIP
                (0, b"PK\x07\x08"),  # ZIP with data descriptor
            ],
            "description": "ZIP Archive (may contain executables)",
            "extensions": [".zip", ".jar", ".war", ".ear", ".apk", ".ipa"],
        },
        "RAR": {
            "signatures": [
                (0, b"Rar!\x1a\x07\x00"),  # RAR 1.5+
                (0, b"Rar!\x1a\x07\x01\x00"),  # RAR 5.0+
            ],
            "description": "RAR Archive",
            "extensions": [".rar"],
        },
        "7ZIP": {
            "signatures": [
                (0, b"7z\xbc\xaf\x27\x1c"),  # 7-Zip
            ],
            "description": "7-Zip Archive",
            "extensions": [".7z"],
        },
        # Script formats that can be malicious
        "PDF": {
            "signatures": [
                (0, b"%PDF-"),  # PDF document
            ],
            "description": "PDF Document (may contain embedded executables)",
            "extensions": [".pdf"],
        },
        "RTF": {
            "signatures": [
                (0, b"{\\rtf"),  # RTF document
            ],
            "description": "Rich Text Format Document",
            "extensions": [".rtf"],
        },
        "DOC": {
            "signatures": [
                (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),  # OLE/COM document
            ],
            "description": "Microsoft Office Document (OLE format)",
            "extensions": [".doc", ".xls", ".ppt", ".msi"],
        },
        "DOCX": {
            "signatures": [
                (0, b"PK\x03\x04"),  # DOCX is ZIP-based
                # Additional check for specific DOCX content will be done
            ],
            "docx_check": True,
            "description": "Microsoft Office Open XML Document",
            "extensions": [".docx", ".xlsx", ".pptx"],
        },
        # Specific malware/packer signatures
        "UPX": {
            "signatures": [
                (0, b"UPX!"),  # UPX packed
            ],
            "description": "UPX Packed Executable",
            "extensions": [],
        },
        "NSIS": {
            "signatures": [
                (4, b"\xef\xbe\xad\xde"),  # NSIS installer
            ],
            "description": "NSIS Installer",
            "extensions": [".exe"],
        },
        # Java formats
        "JAVA_CLASS": {
            "signatures": [
                (0, b"\xca\xfe\xba\xbe"),  # Java class file
            ],
            "description": "Java Class File",
            "extensions": [".class"],
        },
        # Android formats
        "DEX": {
            "signatures": [
                (0, b"dex\n"),  # Android DEX file
            ],
            "description": "Android DEX File",
            "extensions": [".dex"],
        },
        # Flash/ActionScript
        "SWF": {
            "signatures": [
                (0, b"FWS"),  # Flash SWF uncompressed
                (0, b"CWS"),  # Flash SWF compressed
                (0, b"ZWS"),  # Flash SWF LZMA compressed
            ],
            "description": "Adobe Flash SWF File",
            "extensions": [".swf"],
        },
    }

    def __init__(self):
        self.cache: dict[str, dict[str, Any]] = {}

    def detect_file_type(self, file_path: str) -> dict[str, Any]:
        """
        Detect file type using precise magic byte analysis

        Args:
            file_path: Path to file to analyze

        Returns:
            Dictionary with file type information
        """
        path = Path(file_path)

        # Check cache first
        cache_key = f"{path}:{path.stat().st_mtime}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        result: dict[str, Any] = {
            "file_format": "Unknown",
            "format_category": "Unknown",
            "architecture": "Unknown",
            "bits": "Unknown",
            "endianness": "Unknown",
            "confidence": 0.0,
            "is_executable": False,
            "is_archive": False,
            "is_document": False,
            "potential_threat": False,
            "magic_matches": [],
            "file_size": path.stat().st_size if path.exists() else 0,
            "extensions": [],
        }

        if not path.exists() or not path.is_file():
            self.cache[cache_key] = result
            return result

        try:
            with open(path, "rb") as f:
                # Read first 1024 bytes for magic byte analysis
                header = f.read(1024)

                # Check each magic pattern
                for format_name, format_info in self.MAGIC_PATTERNS.items():
                    confidence = self._check_magic_pattern(header, format_info, f)

                    if confidence > 0:
                        result["magic_matches"].append(
                            {
                                "format": format_name,
                                "confidence": confidence,
                                "description": format_info["description"],
                            }
                        )

                        # Update result with highest confidence match
                        if confidence > result["confidence"]:
                            result.update(self._get_format_details(format_name, header, f))
                            result["confidence"] = confidence
                            result["extensions"] = format_info.get("extensions", [])

                # If no magic pattern matched, try fallback detection
                if result["confidence"] == 0:
                    result.update(self._fallback_detection(header, path))

        except Exception as e:
            logger.error(f"Error detecting file type for {path}: {e}")
            result["error"] = str(e)

        # Cache result
        self.cache[cache_key] = result
        return result

    def _check_magic_pattern(
        self,
        header: bytes,
        format_info: dict[str, Any],
        file_handle: BinaryIO,
    ) -> float:
        """Check if header matches magic pattern"""
        signatures = format_info.get("signatures", [])

        for offset, signature in signatures:
            if len(header) >= offset + len(signature):
                if header[offset : offset + len(signature)] == signature:
                    # Basic match found, check for additional validation
                    confidence = 0.8

                    # PE-specific validation
                    if format_info.get("pe_check"):
                        confidence = self._validate_pe_format(header, file_handle)

                    # DOCX-specific validation (ZIP with Office content)
                    elif format_info.get("docx_check"):
                        confidence = self._validate_docx_format(file_handle)

                    if confidence > 0:
                        return confidence

        return 0.0

    def _validate_pe_format(self, header: bytes, file_handle: BinaryIO) -> float:
        """Validate PE format with detailed checks"""
        try:
            if len(header) < 64:
                return 0.0

            # Check DOS header
            if header[0:2] != b"MZ":
                return 0.0

            # Get PE header offset
            pe_offset = struct.unpack("<I", header[60:64])[0]

            if pe_offset > len(header):
                # Need to read more data
                file_handle.seek(pe_offset)
                pe_header = file_handle.read(24)
            else:
                pe_header = header[pe_offset : pe_offset + 24]

            # Check PE signature
            if len(pe_header) >= 4 and pe_header[0:4] == b"PE\x00\x00":
                return 0.95  # High confidence for valid PE

        except Exception as e:
            logger.debug(f"PE validation error: {e}")

        return 0.3  # Low confidence, just DOS header

    def _validate_docx_format(self, file_handle: BinaryIO) -> float:
        """Validate DOCX format (ZIP with Office content)"""
        try:
            file_handle.seek(0)
            header = file_handle.read(512)

            # Check for ZIP signature
            if not header.startswith(b"PK"):
                return 0.0

            # Look for Office-specific content in ZIP central directory
            file_handle.seek(0)
            content = file_handle.read(4096)

            # Look for Office XML namespaces or specific files
            office_indicators = [
                b"word/",
                b"xl/",
                b"ppt/",
                b"[Content_Types].xml",
                b"_rels/",
                b"docProps/",
                b"office",
            ]

            matches = sum(1 for indicator in office_indicators if indicator in content)

            if matches >= 2:
                return 0.9  # High confidence for Office document
            elif matches >= 1:
                return 0.6  # Medium confidence
            else:
                return 0.1  # Low confidence, just ZIP

        except Exception as e:
            logger.debug(f"DOCX validation error: {e}")

        return 0.0

    def _get_format_details(
        self, format_name: str, header: bytes, file_handle: BinaryIO
    ) -> dict[str, Any]:
        """Get detailed information about detected format"""
        details = {
            "file_format": format_name,
            "format_category": self._get_format_category(format_name),
            "is_executable": self._is_executable_format(format_name),
            "is_archive": self._is_archive_format(format_name),
            "is_document": self._is_document_format(format_name),
            "potential_threat": self._is_potential_threat(format_name),
        }

        # Extract architecture and bit information
        if format_name.startswith("ELF"):
            details.update(self._analyze_elf_details(header))
        elif format_name.startswith("MACHO"):
            details.update(self._analyze_macho_details(header))
        elif format_name.startswith("PE"):
            details.update(self._analyze_pe_details(header, file_handle))

        return details

    def _analyze_elf_details(self, header: bytes) -> dict[str, Any]:
        """Analyze ELF format details"""
        if len(header) < 20:
            return {
                "architecture": "Unknown",
                "bits": "Unknown",
                "endianness": "Unknown",
            }

        # ELF header analysis
        bits: int | str = "Unknown"
        if header[4] == 1:
            bits = 32
        elif header[4] == 2:
            bits = 64

        endian: str
        if header[5] == 1:
            endian = "Little"
        elif header[5] == 2:
            endian = "Big"
        else:
            endian = "Unknown"

        # Machine type (offset 18-19 for 32-bit, adjusted for 64-bit)
        machine_offset = 18
        if len(header) > machine_offset + 1:
            machine = struct.unpack(
                "<H" if endian == "Little" else ">H",
                header[machine_offset : machine_offset + 2],
            )[0]

            arch_map = {
                0x03: "x86",
                0x3E: "x86-64",
                0x28: "ARM",
                0xB7: "AArch64",
                0x08: "MIPS",
                0x14: "PowerPC",
                0x15: "PowerPC64",
                0xF3: "RISC-V",
            }

            architecture = arch_map.get(machine, f"Unknown-{machine:04x}")
        else:
            architecture = "Unknown"

        return {"architecture": architecture, "bits": bits, "endianness": endian}

    def _analyze_pe_details(self, header: bytes, file_handle: BinaryIO) -> dict[str, Any]:
        """Analyze PE format details"""
        try:
            if len(header) < 64:
                return {
                    "architecture": "Unknown",
                    "bits": "Unknown",
                    "endianness": "Little",
                }

            pe_offset = struct.unpack("<I", header[60:64])[0]

            if pe_offset > len(header):
                file_handle.seek(pe_offset)
                pe_data = file_handle.read(24)
            else:
                pe_data = header[pe_offset : pe_offset + 24]

            if len(pe_data) < 24:
                return {
                    "architecture": "Unknown",
                    "bits": "Unknown",
                    "endianness": "Little",
                }

            # Machine type is at offset 4 in COFF header (after PE signature)
            machine = struct.unpack("<H", pe_data[4:6])[0]

            machine_map = {
                0x014C: ("x86", 32),
                0x8664: ("x86-64", 64),
                0x01C0: ("ARM", 32),
                0xAA64: ("AArch64", 64),
                0x0200: ("Intel Itanium", 64),
            }

            arch: str
            bits: int | str
            if machine in machine_map:
                arch, bits = machine_map[machine]
            else:
                arch, bits = f"Unknown-{machine:04x}", "Unknown"

            return {"architecture": arch, "bits": bits, "endianness": "Little"}

        except Exception as e:
            logger.debug(f"PE analysis error: {e}")
            return {
                "architecture": "Unknown",
                "bits": "Unknown",
                "endianness": "Little",
            }

    def _analyze_macho_details(self, header: bytes) -> dict[str, Any]:
        """Analyze Mach-O format details"""
        if len(header) < 8:
            return {
                "architecture": "Unknown",
                "bits": "Unknown",
                "endianness": "Unknown",
            }

        magic = struct.unpack("<I", header[0:4])[0]

        # Determine endianness and bits from magic
        bits: int | str
        endian: str
        if magic in [0xFEEDFACE, 0xCEFAEDFE]:  # 32-bit
            bits = 32
            endian = "Big" if magic == 0xFEEDFACE else "Little"
        elif magic in [0xFEEDFACF, 0xCFFAEDFE]:  # 64-bit
            bits = 64
            endian = "Big" if magic == 0xFEEDFACF else "Little"
        elif magic in [0xCAFEBABE, 0xBEBAFECA]:  # Universal
            bits = "Universal"
            endian = "Big" if magic == 0xCAFEBABE else "Little"
        else:
            return {
                "architecture": "Unknown",
                "bits": "Unknown",
                "endianness": "Unknown",
            }

        # CPU type is at offset 4
        if len(header) >= 8:
            cpu_type = struct.unpack("<I" if endian == "Little" else ">I", header[4:8])[0]

            cpu_map = {
                7: "x86",
                0x01000007: "x86-64",
                12: "ARM",
                0x0100000C: "AArch64",
                18: "PowerPC",
                0x01000012: "PowerPC64",
            }

            architecture = cpu_map.get(cpu_type, f"Unknown-{cpu_type:08x}")
        else:
            architecture = "Unknown"

        return {"architecture": architecture, "bits": bits, "endianness": endian}

    def _fallback_detection(self, header: bytes, file_path: Path) -> dict[str, Any]:
        """Fallback detection using file extension and basic heuristics"""
        result = {
            "file_format": "Unknown",
            "format_category": "Unknown",
            "architecture": "Unknown",
            "bits": "Unknown",
            "endianness": "Unknown",
            "is_executable": False,
            "is_archive": False,
            "is_document": False,
            "potential_threat": False,
        }

        # Check file extension
        extension = file_path.suffix.lower()

        executable_exts = [
            ".exe",
            ".dll",
            ".sys",
            ".scr",
            ".com",
            ".bat",
            ".cmd",
            ".ps1",
            ".vbs",
            ".js",
        ]
        archive_exts = [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"]
        document_exts = [
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".ppt",
            ".pptx",
            ".rtf",
        ]

        if extension in executable_exts:
            result["is_executable"] = True
            result["potential_threat"] = True
            result["format_category"] = "Executable"
        elif extension in archive_exts:
            result["is_archive"] = True
            result["format_category"] = "Archive"
        elif extension in document_exts:
            result["is_document"] = True
            result["format_category"] = "Document"

        # Basic heuristics based on header content
        if header:
            # Check for common executable patterns
            if (
                b"\x4d\x5a" in header[:10] or b"\x7f\x45\x4c\x46" in header[:10]  # MZ signature
            ):  # ELF signature
                result["potential_threat"] = True

            # Check for script patterns
            script_patterns = [b"#!/", b"@echo", b"<script", b"eval(", b"function("]
            if any(pattern in header[:512] for pattern in script_patterns):
                result["potential_threat"] = True
                result["format_category"] = "Script"

        return result

    def _get_format_category(self, format_name: str) -> str:
        """Get general category for format"""
        if format_name.startswith(("PE", "ELF", "MACHO")):
            return "Executable"
        elif format_name in ["ZIP", "RAR", "7ZIP"]:
            return "Archive"
        elif format_name in ["PDF", "DOC", "DOCX", "RTF"]:
            return "Document"
        elif format_name in ["SWF", "JAVA_CLASS", "DEX"]:
            return "Bytecode"
        else:
            return "Other"

    def _is_executable_format(self, format_name: str) -> bool:
        """Check if format is executable"""
        return format_name.startswith(("PE", "ELF", "MACHO")) or format_name in [
            "SWF",
            "JAVA_CLASS",
            "DEX",
        ]

    def _is_archive_format(self, format_name: str) -> bool:
        """Check if format is archive"""
        return format_name in ["ZIP", "RAR", "7ZIP"]

    def _is_document_format(self, format_name: str) -> bool:
        """Check if format is document"""
        return format_name in ["PDF", "DOC", "DOCX", "RTF"]

    def _is_potential_threat(self, format_name: str) -> bool:
        """Check if format could be potentially threatening"""
        # Most executable formats and some documents can be threats
        threat_formats = [
            "PE32",
            "ELF32",
            "ELF64",
            "MACHO32",
            "MACHO64",
            "MACHO_UNIVERSAL",
            "PDF",
            "DOC",
            "DOCX",
            "RTF",
            "SWF",
            "JAVA_CLASS",
            "DEX",
            "UPX",
            "NSIS",
        ]
        return format_name in threat_formats

    def clear_cache(self) -> None:
        """Clear detection cache"""
        self.cache.clear()
        logger.debug("Magic byte detection cache cleared")


# Global detector instance
global_detector = MagicByteDetector()


def detect_file_type(file_path: str) -> dict[str, Any]:
    """
    Detect file type using enhanced magic byte detection

    Args:
        file_path: Path to file to analyze

    Returns:
        Dictionary with detailed file type information
    """
    return global_detector.detect_file_type(file_path)


def is_executable_file(file_path: str) -> bool:
    """
    Check if file is an executable format

    Args:
        file_path: Path to file to check

    Returns:
        True if file appears to be executable
    """
    result = detect_file_type(file_path)
    return bool(result.get("is_executable", False))


def get_file_threat_level(file_path: str) -> str:
    """
    Get threat level assessment for file

    Args:
        file_path: Path to file to assess

    Returns:
        Threat level string: 'High', 'Medium', 'Low', 'Unknown'
    """
    result = detect_file_type(file_path)

    if result.get("potential_threat", False):
        if result.get("is_executable", False):
            return "High"
        elif result.get("is_document", False) or result.get("is_archive", False):
            return "Medium"
        else:
            return "Low"
    else:
        return "Low"
