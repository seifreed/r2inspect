#!/usr/bin/env python3
"""Format-related pipeline stages."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..adapters.magic_adapter import MagicAdapter
from ..interfaces import AnalyzerBackend
from ..registry.analyzer_registry import AnalyzerRegistry
from ..utils.analyzer_factory import create_analyzer
from ..utils.hashing import calculate_hashes
from ..utils.logger import get_logger
from ..utils.magic_detector import detect_file_type
from .analysis_pipeline import AnalysisStage

_magic_adapter: MagicAdapter | None = None
_magic_detectors: tuple[Any, Any] | None = None
_magic_initialized = False


def _get_magic_detectors() -> tuple[Any, Any] | None:
    global _magic_adapter, _magic_detectors, _magic_initialized
    if not _magic_initialized:
        _magic_initialized = True
        _magic_adapter = MagicAdapter()
        _magic_detectors = _magic_adapter.create_detectors()
    return _magic_detectors


logger = get_logger(__name__)


class FileInfoStage(AnalysisStage):
    """Extract basic file information and metadata."""

    def __init__(self, adapter: AnalyzerBackend, filename: str):
        super().__init__(
            name="file_info",
            description="Extract basic file information and hashes",
            optional=False,
        )
        self.adapter = adapter
        self.filename = filename
        self.file_path = Path(filename)

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        info: dict[str, Any] = {}

        info["size"] = self.file_path.stat().st_size
        info["path"] = str(self.file_path.absolute())
        info["name"] = self.file_path.name

        if _get_magic_detectors() is not None:
            mime_magic, desc_magic = _get_magic_detectors()  # type: ignore[misc]
            info["mime_type"] = mime_magic.from_file(self.filename)
            info["file_type"] = desc_magic.from_file(self.filename)
        else:
            info["mime_type"] = None
            info["file_type"] = None

        enhanced_detection = detect_file_type(self.filename)
        info["enhanced_detection"] = enhanced_detection

        if enhanced_detection["confidence"] > 0.7:
            info["precise_format"] = enhanced_detection["file_format"]
            info["format_category"] = enhanced_detection["format_category"]
            info["threat_level"] = "High" if enhanced_detection["potential_threat"] else "Low"
            if enhanced_detection["architecture"] != "Unknown":
                info["detected_architecture"] = enhanced_detection["architecture"]
            if enhanced_detection["bits"] != "Unknown":
                info["detected_bits"] = enhanced_detection["bits"]

        hashes = calculate_hashes(self.filename)
        info.update(hashes)

        info_cmd = self.adapter.get_file_info()
        if info_cmd:
            bin_info = info_cmd.get("bin", {})
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


class FormatDetectionStage(AnalysisStage):
    """Detect binary file format using multiple methods."""

    def __init__(self, adapter: AnalyzerBackend, filename: str):
        super().__init__(
            name="format_detection",
            description="Detect binary file format (PE/ELF/Mach-O)",
            optional=False,
            dependencies=["file_info"],
        )
        self.adapter = adapter
        self.filename = filename

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
        logger.info(f"Detected file format: {file_format}")

        return {"format_detection": {"file_format": file_format}}

    def _detect_via_r2(self) -> str | None:
        info_cmd = self.adapter.get_file_info()
        if not info_cmd or "bin" not in info_cmd:
            return None

        bin_format = info_cmd["bin"].get("format", "").upper()
        format_map = {"PE": "PE", "ELF": "ELF", "MACH": "Mach-O"}

        for key, value in format_map.items():
            if key in bin_format:
                return value
        return None

    def _detect_via_enhanced_magic(self) -> str | None:
        enhanced_detection = detect_file_type(self.filename)
        if enhanced_detection["confidence"] <= 0.7:
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
        if _get_magic_detectors() is None:
            return None
        _, desc_magic = _get_magic_detectors()  # type: ignore[misc]
        file_type = desc_magic.from_file(self.filename).lower()

        if "pe32" in file_type or "ms-dos" in file_type:
            return "PE"
        if "elf" in file_type:
            return "ELF"
        if "mach-o" in file_type:
            return "Mach-O"

        return None


class FormatAnalysisStage(AnalysisStage):
    """Perform format-specific deep analysis."""

    def __init__(
        self,
        registry: AnalyzerRegistry,
        adapter: AnalyzerBackend,
        config: Any,
        filename: str,
    ) -> None:
        super().__init__(
            name="format_analysis",
            description="Format-specific deep analysis",
            optional=True,
            dependencies=["format_detection"],
            condition=lambda ctx: ctx.get("metadata", {}).get("file_format")
            in {"PE", "ELF", "Mach-O"},
        )
        self.registry = registry
        self.adapter = adapter
        self.config = config
        self.filename = filename

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        file_format = context.get("metadata", {}).get("file_format", "Unknown")

        results: dict[str, Any] = {}
        if file_format == "PE":
            res = self._analyze_pe(context)
            if res is not None:
                results.update(res)
        elif file_format == "ELF":
            res = self._analyze_elf(context)
            if res is not None:
                results.update(res)
        elif file_format == "Mach-O":
            res = self._analyze_macho(context)
            if res is not None:
                results.update(res)
        else:
            logger.info(f"No format-specific analyzer for: {file_format}")

        return results

    def _analyze_pe(self, context: dict[str, Any]) -> dict[str, Any] | None:
        pe_analyzer_class = self.registry.get_analyzer_class("pe_analyzer")
        if pe_analyzer_class:
            analyzer = create_analyzer(
                pe_analyzer_class,
                adapter=self.adapter,
                config=self.config,
                filename=self.filename,
            )
            data = analyzer.analyze()
            self._run_optional_pe_analyzers(data)
            context["results"]["pe_info"] = data
            return {"pe_info": data}
        return None

    def _analyze_elf(self, context: dict[str, Any]) -> dict[str, Any] | None:
        elf_analyzer_class = self.registry.get_analyzer_class("elf_analyzer")
        if elf_analyzer_class:
            analyzer = create_analyzer(elf_analyzer_class, adapter=self.adapter, config=self.config)
            data = analyzer.analyze()
            context["results"]["elf_info"] = data
            return {"elf_info": data}
        return None

    def _analyze_macho(self, context: dict[str, Any]) -> dict[str, Any] | None:
        macho_analyzer_class = self.registry.get_analyzer_class("macho_analyzer")
        if macho_analyzer_class:
            analyzer = create_analyzer(
                macho_analyzer_class, adapter=self.adapter, config=self.config
            )
            data = analyzer.analyze()
            context["results"]["macho_info"] = data
            return {"macho_info": data}
        return None

    def _run_optional_pe_analyzers(self, pe_info: dict[str, Any]) -> None:
        analyzers = [
            ("analyze_authenticode", "authenticode", "authenticode"),
            ("analyze_overlay", "overlay_analyzer", "overlay"),
            ("analyze_resources", "resource_analyzer", "resources"),
            ("analyze_mitigations", "exploit_mitigation", "exploit_mitigations"),
        ]

        for config_key, analyzer_name, result_key in analyzers:
            if not getattr(self.config, config_key, False):
                continue
            analyzer_class = self.registry.get_analyzer_class(analyzer_name)
            if not analyzer_class:
                continue
            analyzer = create_analyzer(
                analyzer_class,
                adapter=self.adapter,
                config=self.config,
                filename=self.filename,
            )
            pe_info[result_key] = analyzer.analyze()
