#!/usr/bin/env python3
"""Format-related pipeline stages."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ..interfaces import (
    AnalyzerBackend,
    FileTypeDetectorLike,
    HashCalculatorLike,
    MagicDetectorProviderLike,
)
from .analysis_pipeline import AnalysisStage
from .pipeline_runtime_common import (
    default_file_type_detector as _default_file_type_detector,
    default_hash_calculator as _default_hash_calculator,
    detect_via_header_bytes as _detect_via_header_bytes_impl,
)
from .stages_format_analysis import FormatAnalysisStage

logger = logging.getLogger(__name__)

_magic_initialized = False
_magic_detectors: tuple[Any, Any] | None = None
_magic_adapter: Any | None = None


def _resolved_path(path: str) -> str:
    """Return an absolute resolved path to avoid symlink-dependent magic detection."""
    try:
        return str(Path(path).resolve())
    except Exception:
        return path


def _get_magic_detectors() -> tuple[Any, Any] | None:
    """Return cached magic detectors for legacy callers."""
    return _magic_detectors


def _detect_via_header_bytes(filename: str) -> str | None:
    return _detect_via_header_bytes_impl(filename)


class FileInfoStage(AnalysisStage):
    """Extract basic file information and metadata."""

    def __init__(
        self,
        adapter: AnalyzerBackend,
        filename: str,
        hash_calculator: HashCalculatorLike = _default_hash_calculator,
        file_type_detector: FileTypeDetectorLike = _default_file_type_detector,
        magic_detector_provider: MagicDetectorProviderLike | None = None,
    ):
        super().__init__(
            name="file_info",
            description="Extract basic file information and hashes",
            optional=False,
        )
        self.adapter = adapter
        self.filename = filename
        self.file_path = Path(filename)
        self.hash_calculator = hash_calculator
        self.file_type_detector = file_type_detector
        self.magic_detector_provider = magic_detector_provider

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        info: dict[str, Any] = {}

        info["size"] = self.file_path.stat().st_size
        info["path"] = str(self.file_path.absolute())
        info["name"] = self.file_path.name

        detectors = self._get_magic_detectors()
        if detectors is not None:
            mime_magic, desc_magic = detectors
            resolved_path = _resolved_path(self.filename)
            info["mime_type"] = mime_magic.from_file(resolved_path)
            info["file_type"] = desc_magic.from_file(resolved_path)
        else:
            info["mime_type"] = None
            info["file_type"] = None

        enhanced_detection = self.file_type_detector(self.filename)
        info["enhanced_detection"] = enhanced_detection

        if enhanced_detection["confidence"] > 0.7:
            info["precise_format"] = enhanced_detection["file_format"]
            info["format_category"] = enhanced_detection["format_category"]
            info["threat_level"] = "High" if enhanced_detection["potential_threat"] else "Low"
            if enhanced_detection["architecture"] != "Unknown":
                info["detected_architecture"] = enhanced_detection["architecture"]
            if enhanced_detection["bits"] != "Unknown":
                info["detected_bits"] = enhanced_detection["bits"]

        hashes = self.hash_calculator(self.filename)
        info.update(hashes)

        info_cmd = self.adapter.get_file_info()
        if info_cmd and "bin" in info_cmd:
            bin_info = info_cmd["bin"]
            arch = bin_info.get("arch", "Unknown")
            bits = bin_info.get("bits", "Unknown")

            if arch == "x86" and bits == 64:
                arch = "x86-64"
            elif arch == "x86" and bits == 32:
                arch = "x86"

            info["architecture"] = arch
            info["bits"] = bits
            info["endian"] = bin_info.get("endian", "Unknown")

        context["results"]["file_info"] = info
        return {"file_info": info}

    def _get_magic_detectors(self) -> tuple[Any, Any] | None:
        global _magic_initialized, _magic_detectors

        if self.magic_detector_provider is not None:
            detectors = self.magic_detector_provider.get_detectors()
            _magic_initialized = True
            _magic_detectors = detectors
            return detectors

        _magic_initialized = True
        return _get_magic_detectors()


class FormatDetectionStage(AnalysisStage):
    """Detect binary file format using multiple methods."""

    def __init__(
        self,
        adapter: AnalyzerBackend,
        filename: str,
        file_type_detector: FileTypeDetectorLike = _default_file_type_detector,
        magic_detector_provider: MagicDetectorProviderLike | None = None,
    ):
        super().__init__(
            name="format_detection",
            description="Detect binary file format (PE/ELF/Mach-O)",
            optional=False,
            dependencies=["file_info"],
        )
        self.adapter = adapter
        self.filename = filename
        self.file_type_detector = file_type_detector
        self.magic_detector_provider = magic_detector_provider

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        if "metadata" not in context:
            context["metadata"] = {}

        file_format = self._detect_via_r2()
        if not file_format:
            file_format = self._detect_via_enhanced_magic()
        if not file_format:
            file_format = self._detect_via_basic_magic()
        if not file_format:
            file_format = "Unknown"

        context["metadata"]["file_format"] = file_format
        logger.info("Detected file format: %s", file_format)

        return {"format_detection": {"file_format": file_format}}

    def _detect_via_r2(self) -> str | None:
        info_cmd = self.adapter.get_file_info()
        if not info_cmd or "bin" not in info_cmd:
            return None

        bin_info = info_cmd["bin"]
        bin_format = (
            str(bin_info.get("format", ""))
            or str(bin_info.get("class", ""))
            or str(bin_info.get("bintype", ""))
            or str(info_cmd.get("core", {}).get("format", ""))
        ).upper()
        format_map = {"PE": "PE", "ELF": "ELF", "MACH": "Mach-O"}

        for key, value in format_map.items():
            if key in bin_format:
                return value
        return None

    def _detect_via_enhanced_magic(self) -> str | None:
        enhanced_detection = self.file_type_detector(self.filename)
        if enhanced_detection["confidence"] <= 0.7:
            if enhanced_detection["confidence"] > 0.0 and enhanced_detection[
                "file_format"
            ].startswith("PE"):
                return "PE"
            return None

        format_name = enhanced_detection["file_format"]
        format_map = {
            "PE": "PE",
            "ELF": "ELF",
            "MACHO": "Mach-O",
            "JAVA_CLASS": "Java",
            "DEX": "Android",
        }

        for prefix, result in format_map.items():
            if format_name.startswith(prefix) or format_name == prefix:
                return result

        if format_name in ["ZIP", "RAR", "7ZIP"]:
            return "Archive"
        if format_name in ["PDF", "DOC", "DOCX", "RTF"]:
            return "Document"

        return None

    def _detect_via_basic_magic(self) -> str | None:
        if self.magic_detector_provider is not None:
            detectors = self.magic_detector_provider.get_detectors()
        else:
            detectors = _get_magic_detectors()
        if detectors is None:
            return _detect_via_header_bytes(self.filename)
        _, desc_magic = detectors
        file_type = desc_magic.from_file(_resolved_path(self.filename)).lower()

        if "pe32" in file_type or "ms-dos" in file_type:
            return "PE"
        if "elf" in file_type:
            return "ELF"
        if "mach-o" in file_type:
            return "Mach-O"

        return None
