#!/usr/bin/env python3
"""Canonical access to enhanced magic-byte detection."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any, BinaryIO

from ..infrastructure.logging import get_logger
from .magic_detector_support import (
    analyze_elf_details as _analyze_elf_details_impl,
    analyze_macho_details as _analyze_macho_details_impl,
    analyze_pe_details as _analyze_pe_details_impl,
    fallback_detection as _fallback_detection_impl,
    read_at_offset as _read_at_offset_impl,
    validate_docx_format as _validate_docx_format_impl,
    validate_pe_format as _validate_pe_format_impl,
)
from .magic_patterns import MAGIC_PATTERNS as _MAGIC_PATTERNS

logger = get_logger(__name__)


class MagicByteDetector:
    """Enhanced file type detection with precise magic byte patterns."""

    MAGIC_PATTERNS: dict[str, dict[str, Any]] = _MAGIC_PATTERNS

    def __init__(self) -> None:
        self.cache: dict[str, dict[str, Any]] = {}

    def detect_file_type(self, file_path: str) -> dict[str, Any]:
        path = Path(file_path)
        mtime = path.stat().st_mtime if path.exists() else 0
        cache_key = f"{path}:{mtime}"
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

        # Reject special files that could block indefinitely on read
        # (e.g., /dev/zero, named pipes, device nodes)
        try:
            if not path.stat().st_mode & 0o100000:  # S_IFREG — regular file check
                self.cache[cache_key] = result
                return result
        except OSError:
            self.cache[cache_key] = result
            return result

        try:
            with open(path, "rb") as file_handle:
                header = file_handle.read(1024)
                for format_name, format_info in self.MAGIC_PATTERNS.items():
                    confidence = self._check_magic_pattern(header, format_info, file_handle)
                    if confidence <= 0:
                        continue
                    result["magic_matches"].append(
                        {
                            "format": format_name,
                            "confidence": confidence,
                            "description": format_info["description"],
                        }
                    )
                    if confidence > result["confidence"]:
                        result.update(self._get_format_details(format_name, header, file_handle))
                        result["confidence"] = confidence
                        result["extensions"] = format_info.get("extensions", [])

                if result["confidence"] == 0:
                    result.update(self._fallback_detection(header, path))
        except Exception as exc:
            logger.error("Error detecting file type for %s: %s", path, exc)
            result["error"] = str(exc)

        self.cache[cache_key] = result
        return result

    def _check_magic_pattern(
        self, header: bytes, format_info: dict[str, Any], file_handle: BinaryIO
    ) -> float:
        for offset, signature in format_info.get("signatures", []):
            if len(header) < offset + len(signature):
                continue
            if header[offset : offset + len(signature)] != signature:
                continue
            confidence = 0.8
            if format_info.get("pe_check"):
                confidence = self._validate_pe_format(header, file_handle)
            elif format_info.get("docx_check"):
                confidence = self._validate_docx_format(file_handle)
            if confidence > 0:
                return confidence
        return 0.0

    def _validate_pe_format(self, header: bytes, file_handle: BinaryIO) -> float:
        return _validate_pe_format_impl(header, file_handle, logger)

    def _validate_docx_format(self, file_handle: BinaryIO) -> float:
        return _validate_docx_format_impl(file_handle, logger)

    def _get_format_details(
        self, format_name: str, header: bytes, file_handle: BinaryIO
    ) -> dict[str, Any]:
        details = {
            "file_format": format_name,
            "format_category": self._get_format_category(format_name),
            "is_executable": self._is_executable_format(format_name),
            "is_archive": self._is_archive_format(format_name),
            "is_document": self._is_document_format(format_name),
            "potential_threat": self._is_potential_threat(format_name),
        }
        if format_name.startswith("ELF"):
            details.update(self._analyze_elf_details(header))
        elif format_name.startswith("MACHO"):
            details.update(self._analyze_macho_details(header))
        elif format_name.startswith("PE"):
            details.update(self._analyze_pe_details(header, file_handle))
        return details

    def _analyze_elf_details(self, header: bytes) -> dict[str, Any]:
        return _analyze_elf_details_impl(header)

    def _analyze_pe_details(self, header: bytes, file_handle: BinaryIO) -> dict[str, Any]:
        return _analyze_pe_details_impl(header, file_handle, logger)

    def _analyze_macho_details(self, header: bytes) -> dict[str, Any]:
        return _analyze_macho_details_impl(header)

    def _fallback_detection(self, header: bytes, file_path: Path) -> dict[str, Any]:
        return _fallback_detection_impl(header, file_path)

    def _get_format_category(self, format_name: str) -> str:
        if format_name.startswith(("PE", "ELF", "MACHO")):
            return "Executable"
        if format_name in ["ZIP", "RAR", "7ZIP"]:
            return "Archive"
        if format_name in ["PDF", "DOC", "DOCX", "RTF"]:
            return "Document"
        if format_name in ["SWF", "JAVA_CLASS", "DEX"]:
            return "Bytecode"
        return "Other"

    def _is_executable_format(self, format_name: str) -> bool:
        return format_name.startswith(("PE", "ELF", "MACHO")) or format_name in [
            "SWF",
            "JAVA_CLASS",
            "DEX",
        ]

    def _is_archive_format(self, format_name: str) -> bool:
        return format_name in ["ZIP", "RAR", "7ZIP"]

    def _is_document_format(self, format_name: str) -> bool:
        return format_name in ["PDF", "DOC", "DOCX", "RTF"]

    def _is_potential_threat(self, format_name: str) -> bool:
        return format_name in [
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

    def clear_cache(self) -> None:
        self.cache.clear()
        logger.debug("Magic byte detection cache cleared")


def _read_at_offset(file_handle: BinaryIO, offset: int, size: int) -> bytes:
    return _read_at_offset_impl(file_handle, offset, size)


global_detector = MagicByteDetector()


def detect_file_type(file_path: str) -> dict[str, Any]:
    return global_detector.detect_file_type(file_path)


def is_executable_file(file_path: str) -> bool:
    return bool(detect_file_type(file_path).get("is_executable", False))


def get_file_threat_level(file_path: str) -> str:
    result = detect_file_type(file_path)
    if result.get("potential_threat", False):
        if result.get("is_executable", False):
            return "High"
        if result.get("is_document", False) or result.get("is_archive", False):
            return "Medium"
        return "Low"
    return "Low"
