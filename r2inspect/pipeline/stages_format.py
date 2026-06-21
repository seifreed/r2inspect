#!/usr/bin/env python3
"""Format-related pipeline stages."""

from __future__ import annotations

import logging
from collections.abc import Callable
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
from .stages_common import _results_bucket
from .stages_format_analysis import FormatAnalysisStage

logger = logging.getLogger(__name__)

_magic_initialized = False
_magic_detectors: tuple[Any, Any] | None = None
_magic_adapter: Any | None = None


def _default_resolver(path: str) -> str:
    return str(Path(path).resolve())


def _resolved_path(path: str, resolver: Callable[[str], str] = _default_resolver) -> str:
    """Return an absolute resolved path to avoid symlink-dependent magic detection."""
    try:
        return resolver(path)
    except Exception:
        return path


def _metadata_bucket(context: dict[str, Any]) -> dict[str, Any]:
    metadata = context.get("metadata")
    if isinstance(metadata, dict):
        return metadata
    metadata = {}
    context["metadata"] = metadata
    return metadata


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
        info: dict[str, Any] = {
            "size": self.file_path.stat().st_size,
            "path": str(self.file_path.absolute()),
            "name": self.file_path.name,
        }
        info.update(self._magic_info())

        enhanced_detection = self.file_type_detector(self.filename)
        info["enhanced_detection"] = enhanced_detection
        info.update(self._enhanced_detection_info(enhanced_detection))

        hash_info = self.hash_calculator(self.filename)
        if isinstance(hash_info, dict):
            info.update(hash_info)
        info.update(self._bin_arch_info(self.adapter.get_file_info()))

        _results_bucket(context)["file_info"] = info
        return {"file_info": info}

    def _magic_info(self) -> dict[str, Any]:
        detectors = self._get_magic_detectors()
        if detectors is None:
            return {"mime_type": None, "file_type": None}
        mime_magic, desc_magic = detectors
        resolved_path = _resolved_path(self.filename)
        try:
            mime_type = mime_magic.from_file(resolved_path)
            file_type = desc_magic.from_file(resolved_path)
        except FileNotFoundError:
            logger.warning(
                "libmagic could not read %s for file-type detection; reporting unknown type",
                resolved_path,
            )
            return {"mime_type": None, "file_type": None}
        return {
            "mime_type": mime_type,
            "file_type": file_type,
        }

    @staticmethod
    def _enhanced_detection_info(enhanced_detection: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(enhanced_detection, dict):
            return {}

        try:
            confidence = float(enhanced_detection.get("confidence", 0.0))
        except (TypeError, ValueError):
            return {}

        if confidence <= 0.7:
            return {}
        info: dict[str, Any] = {
            "precise_format": enhanced_detection.get("file_format", "Unknown"),
            "format_category": enhanced_detection.get("format_category", "Unknown"),
            "threat_level": "High" if enhanced_detection.get("potential_threat") else "Low",
        }
        architecture = enhanced_detection.get("architecture", "Unknown")
        bits = enhanced_detection.get("bits", "Unknown")
        if architecture != "Unknown":
            info["detected_architecture"] = architecture
        if bits != "Unknown":
            info["detected_bits"] = bits
        return info

    @staticmethod
    def _bin_arch_info(info_cmd: dict[str, Any] | None) -> dict[str, Any]:
        if not (isinstance(info_cmd, dict) and isinstance(info_cmd.get("bin"), dict)):
            return {}
        bin_info = info_cmd["bin"]
        arch = bin_info.get("arch", "Unknown")
        bits = bin_info.get("bits", "Unknown")
        if arch == "x86" and bits == 64:
            arch = "x86-64"
        return {
            "architecture": arch,
            "bits": bits,
            "endian": bin_info.get("endian", "Unknown"),
        }

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
        file_format = self._detect_via_r2()
        if not file_format:
            file_format = self._detect_via_enhanced_magic()
        if not file_format:
            file_format = self._detect_via_basic_magic()
        if not file_format:
            file_format = "Unknown"

        _metadata_bucket(context)["file_format"] = file_format
        logger.info("Detected file format: %s", file_format)

        return {"format_detection": {"file_format": file_format}}

    def _detect_via_r2(self) -> str | None:
        info_cmd = self.adapter.get_file_info()
        if not isinstance(info_cmd, dict) or not isinstance(info_cmd.get("bin"), dict):
            return None

        bin_info = info_cmd["bin"]
        core_info = info_cmd.get("core")
        core_format = str(core_info.get("format", "")) if isinstance(core_info, dict) else ""
        bin_format = (
            str(bin_info.get("format", ""))
            or str(bin_info.get("class", ""))
            or str(bin_info.get("bintype", ""))
            or core_format
        ).upper()
        format_map = {"PE": "PE", "ELF": "ELF", "MACH": "Mach-O"}

        for key, value in format_map.items():
            if key in bin_format:
                return value
        return None

    def _detect_via_enhanced_magic(self) -> str | None:
        enhanced_detection = self.file_type_detector(self.filename)
        if not isinstance(enhanced_detection, dict):
            return None

        try:
            confidence = float(enhanced_detection.get("confidence", 0.0))
        except (TypeError, ValueError):
            return None

        file_format = str(enhanced_detection.get("file_format", ""))

        if confidence <= 0.7:
            if confidence > 0.0 and file_format.startswith("PE"):
                return "PE"
            return None

        format_map = {
            "PE": "PE",
            "ELF": "ELF",
            "MACHO": "Mach-O",
            "JAVA_CLASS": "Java",
            "DEX": "Android",
        }

        for prefix, result in format_map.items():
            if file_format.startswith(prefix) or file_format == prefix:
                return result

        if file_format in ["ZIP", "RAR", "7ZIP"]:
            return "Archive"
        if file_format in ["PDF", "DOC", "DOCX", "RTF"]:
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
        try:
            file_type = desc_magic.from_file(_resolved_path(self.filename)).lower()
        except FileNotFoundError:
            return None

        if "pe32" in file_type or "ms-dos" in file_type:
            return "PE"
        if "elf" in file_type:
            return "ELF"
        if "mach-o" in file_type:
            return "Mach-O"

        return None


__all__ = [
    "FormatAnalysisStage",
]
