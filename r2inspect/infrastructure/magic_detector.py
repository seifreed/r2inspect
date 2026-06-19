#!/usr/bin/env python3
"""Canonical access to enhanced magic-byte detection."""

from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
from typing import Any, BinaryIO

from ..infrastructure.logging import get_logger
from .magic_detector_support import (
    THREAT_FORMATS as _THREAT_FORMATS,
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
    MAGIC_PATTERNS: dict[str, dict[str, Any]] = _MAGIC_PATTERNS
    _EXEC_EXTRA = ("SWF", "JAVA_CLASS", "DEX")
    # Bound the cache: ``global_detector`` is process-global and gets one entry
    # per analyzed file, so an unbounded dict leaks memory over a long batch.
    CACHE_MAX_ENTRIES = 1024

    def __init__(self) -> None:
        self.cache: OrderedDict[str, dict[str, Any]] = OrderedDict()

    def detect_file_type(self, file_path: str) -> dict[str, Any]:
        path = Path(file_path)
        mtime = path.stat().st_mtime if path.exists() else 0
        cache_key = f"{path}:{mtime}"
        if cache_key in self.cache:
            self.cache.move_to_end(cache_key)
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
        if not self._is_readable_regular_file(path):
            self._store(cache_key, result)
            return result

        try:
            with open(path, "rb") as file_handle:
                header = file_handle.read(1024)
                self._scan_magic_patterns(header, file_handle, result)
                if result["confidence"] == 0:
                    fallback = self._fallback_detection(header, path)
                    if isinstance(fallback, dict):
                        result.update(fallback)
        except Exception as exc:
            logger.error("Error detecting file type for %s: %s", path, exc)
            result["error"] = str(exc)

        self._store(cache_key, result)
        return result

    def _store(self, cache_key: str, result: dict[str, Any]) -> None:
        self.cache[cache_key] = result
        while len(self.cache) > self.CACHE_MAX_ENTRIES:
            self.cache.popitem(last=False)

    @staticmethod
    def _is_readable_regular_file(path: Path) -> bool:
        # Reject special files (e.g. /dev/zero, pipes, device nodes) that could block on read.
        if not path.exists() or not path.is_file():
            return False
        try:
            return bool(path.stat().st_mode & 0o100000)  # S_IFREG — regular file check
        except OSError:
            return False

    def _scan_magic_patterns(
        self, header: bytes, file_handle: BinaryIO, result: dict[str, Any]
    ) -> None:
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
                details = self._get_format_details(format_name, header, file_handle)
                if isinstance(details, dict):
                    result.update(details)
                result["confidence"] = confidence
                result["extensions"] = format_info.get("extensions", [])

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
        if format_name in self._EXEC_EXTRA:
            return "Bytecode"
        return "Other"

    def _is_executable_format(self, format_name: str) -> bool:
        return format_name.startswith(("PE", "ELF", "MACHO")) or format_name in self._EXEC_EXTRA

    def _is_archive_format(self, format_name: str) -> bool:
        return format_name in ["ZIP", "RAR", "7ZIP"]

    def _is_document_format(self, format_name: str) -> bool:
        return format_name in ["PDF", "DOC", "DOCX", "RTF"]

    def _is_potential_threat(self, format_name: str) -> bool:
        return format_name in _THREAT_FORMATS

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
