#!/usr/bin/env python3
"""
Predefined Analysis Pipeline Stages

This module provides concrete implementations of common analysis stages
used in binary analysis workflows. Each stage is self-contained and focuses
on a specific aspect of binary analysis.

Stages are organized by analysis category:
    - File Information: Basic file metadata and hashing
    - Format Detection: Identify binary format (PE/ELF/Mach-O)
    - Format Analysis: Format-specific deep analysis
    - Hashing: Fuzzy hashing and similarity detection
    - Detection: Packer, crypto, anti-analysis detection
    - Security: Exploit mitigations and signatures
    - Metadata: Sections, imports, exports, functions

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

from pathlib import Path
from typing import Any

try:
    import magic
except Exception:  # pragma: no cover - optional dependency
    magic = None

from ..adapters.r2pipe_adapter import R2PipeAdapter
from ..registry.analyzer_registry import AnalyzerCategory, AnalyzerRegistry
from ..utils.hashing import calculate_hashes
from ..utils.logger import get_logger
from ..utils.magic_detector import detect_file_type
from ..utils.r2_helpers import safe_cmdj
from .analysis_pipeline import AnalysisStage

logger = get_logger(__name__)


class FileInfoStage(AnalysisStage):
    """
    Extract basic file information and metadata.

    Performs initial file analysis including:
        - File size, path, and name
        - MIME type detection
        - Enhanced magic byte detection
        - Cryptographic hashes (MD5, SHA1, SHA256)
        - Architecture and bits detection

    This stage should typically run first in the pipeline as its output
    is used by subsequent stages.
    """

    def __init__(self, adapter: R2PipeAdapter, filename: str):
        """
        Initialize file info stage.

        Args:
            adapter: R2Pipe adapter for radare2 operations
            filename: Path to file being analyzed
        """
        super().__init__(
            name="file_info",
            description="Extract basic file information and hashes",
            optional=False,
        )
        self.adapter = adapter
        self.filename = filename
        self.file_path = Path(filename)

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        """Execute file info extraction."""
        info: dict[str, Any] = {}

        # Basic file attributes
        info["size"] = self.file_path.stat().st_size
        info["path"] = str(self.file_path.absolute())
        info["name"] = self.file_path.name

        # MIME type detection (python-magic optional)
        if magic is not None:
            info["mime_type"] = magic.from_file(self.filename, mime=True)
            info["file_type"] = magic.from_file(self.filename)
        else:
            info["mime_type"] = None
            info["file_type"] = None

        # Enhanced magic byte detection
        enhanced_detection = detect_file_type(self.filename)
        info["enhanced_detection"] = enhanced_detection

        # Use enhanced detection if high confidence
        if enhanced_detection["confidence"] > 0.7:
            info["precise_format"] = enhanced_detection["file_format"]
            info["format_category"] = enhanced_detection["format_category"]
            info["threat_level"] = "High" if enhanced_detection["potential_threat"] else "Low"
            if enhanced_detection["architecture"] != "Unknown":
                info["detected_architecture"] = enhanced_detection["architecture"]
            if enhanced_detection["bits"] != "Unknown":
                info["detected_bits"] = enhanced_detection["bits"]

        # Cryptographic hashes
        hashes = calculate_hashes(self.filename)
        info.update(hashes)

        # Architecture info from radare2
        info_cmd = safe_cmdj(self.adapter._r2, "ij", {})
        if info_cmd:
            bin_info = info_cmd.get("bin", {})
            arch = bin_info.get("arch", "Unknown")
            bits = bin_info.get("bits", "Unknown")

            # Normalize architecture naming
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
    """
    Detect binary file format using multiple methods.

    Uses a fallback strategy to detect format:
        1. Radare2 detection (ij command)
        2. Enhanced magic byte detection
        3. Basic magic library detection

    The detected format is stored in context["metadata"]["file_format"]
    for use by subsequent format-specific stages.
    """

    def __init__(self, adapter: R2PipeAdapter, filename: str):
        """
        Initialize format detection stage.

        Args:
            adapter: R2Pipe adapter for radare2 operations
            filename: Path to file being analyzed
        """
        super().__init__(
            name="format_detection",
            description="Detect binary file format (PE/ELF/Mach-O)",
            optional=False,
            dependencies=["file_info"],
        )
        self.adapter = adapter
        self.filename = filename

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        """Execute format detection."""
        if "metadata" not in context:
            context["metadata"] = {}

        # Try radare2 detection first
        file_format = self._detect_via_r2()

        # Fallback to enhanced magic
        if not file_format:
            file_format = self._detect_via_enhanced_magic()

        # Final fallback to basic magic
        if not file_format:
            file_format = self._detect_via_basic_magic()

        # Default to Unknown if all methods fail
        if not file_format:
            file_format = "Unknown"

        context["metadata"]["file_format"] = file_format
        logger.info(f"Detected file format: {file_format}")

        return {"format_detection": {"file_format": file_format}}

    def _detect_via_r2(self) -> str | None:
        """Detect format using radare2."""
        info_cmd = safe_cmdj(self.adapter._r2, "ij", {})
        if not info_cmd or "bin" not in info_cmd:
            return None

        bin_format = info_cmd["bin"].get("format", "").upper()
        format_map = {"PE": "PE", "ELF": "ELF", "MACH": "Mach-O"}

        for key, value in format_map.items():
            if key in bin_format:
                return value
        return None

    def _detect_via_enhanced_magic(self) -> str | None:
        """Detect format using enhanced magic detection."""
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

        # Check archive and document formats
        if format_name in ["ZIP", "RAR", "7ZIP"]:
            return "Archive"
        if format_name in ["PDF", "DOC", "DOCX", "RTF"]:
            return "Document"

        return None

    def _detect_via_basic_magic(self) -> str | None:
        """Detect format using basic magic library."""
        if magic is None:
            return None
        file_type = magic.from_file(self.filename).lower()

        if "pe32" in file_type or "ms-dos" in file_type:
            return "PE"
        elif "elf" in file_type:
            return "ELF"
        elif "mach-o" in file_type:
            return "Mach-O"

        return None


class FormatAnalysisStage(AnalysisStage):
    """
    Perform format-specific deep analysis.

    Executes format-specific analyzers based on detected file format.
    Uses the registry to retrieve and instantiate appropriate analyzers.

    Supports:
        - PE: PE format analyzer
        - ELF: ELF format analyzer
        - Mach-O: Mach-O format analyzer
    """

    def __init__(self, registry: AnalyzerRegistry, adapter: R2PipeAdapter, config, filename: str):
        """
        Initialize format analysis stage.

        Args:
            registry: Analyzer registry for dynamic analyzer lookup
            adapter: R2Pipe adapter for radare2 operations
            config: Configuration object
            filename: Path to file being analyzed
        """
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
        """Execute format-specific analysis."""
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
        """Analyze PE format."""
        pe_analyzer_class = self.registry.get_analyzer_class("pe_analyzer")
        if pe_analyzer_class:
            analyzer = pe_analyzer_class(self.adapter._r2, self.config, self.filename)
            data = analyzer.analyze()
            context["results"]["pe_info"] = data
            return {"pe_info": data}
        return None

    def _analyze_elf(self, context: dict[str, Any]) -> dict[str, Any] | None:
        """Analyze ELF format."""
        elf_analyzer_class = self.registry.get_analyzer_class("elf_analyzer")
        if elf_analyzer_class:
            analyzer = elf_analyzer_class(self.adapter._r2, self.config)
            data = analyzer.analyze()
            context["results"]["elf_info"] = data
            return {"elf_info": data}
        return None

    def _analyze_macho(self, context: dict[str, Any]) -> dict[str, Any] | None:
        """Analyze Mach-O format."""
        macho_analyzer_class = self.registry.get_analyzer_class("macho_analyzer")
        if macho_analyzer_class:
            analyzer = macho_analyzer_class(self.adapter._r2, self.config)
            data = analyzer.analyze()
            context["results"]["macho_info"] = data
            return {"macho_info": data}
        return None


class HashingStage(AnalysisStage):
    """
    Execute hashing analyzers for similarity detection.

    Runs all registered hashing analyzers including:
        - SSDeep: Fuzzy hashing
        - TLSH: Locality-sensitive hashing
        - Telfhash: ELF-specific hashing
        - Impfuzzy: PE import hashing
        - CCBHash: Control flow hashing
        - SimHash: Similarity hashing
    """

    def __init__(self, registry: AnalyzerRegistry, adapter: R2PipeAdapter, config, filename: str):
        """
        Initialize hashing stage.

        Args:
            registry: Analyzer registry for dynamic analyzer lookup
            adapter: R2Pipe adapter for radare2 operations
            config: Configuration object
            filename: Path to file being analyzed
        """
        super().__init__(
            name="hashing",
            description="Execute fuzzy and similarity hashing",
            optional=True,
            dependencies=["file_info"],
        )
        self.registry = registry
        self.adapter = adapter
        self.config = config
        self.filename = filename

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        """Execute hashing analyzers."""
        file_format = context.get("metadata", {}).get("file_format", "Unknown")

        hashing_analyzers = self.registry.get_by_category(AnalyzerCategory.HASHING)

        results: dict[str, Any] = {}
        for name, analyzer_class in hashing_analyzers.items():
            try:
                if not self._supports_format(name, file_format):
                    logger.debug(f"Skipping {name}: doesn't support {file_format}")
                    continue
                analyzer = self._build_hashing_analyzer(analyzer_class)
                result = self._run_hashing_analyzer(name, analyzer)
                self._store_hashing_result(context, results, name, result)
            except Exception as e:
                logger.warning(f"Hashing analyzer '{name}' failed: {e}")
                context["results"][name] = {"error": str(e)}

        return results

    def _supports_format(self, name: str, file_format: str) -> bool:
        """Check if analyzer supports the file format."""
        metadata = self.registry.get_metadata(name)
        return not (metadata and not metadata.supports_format(file_format))

    def _build_hashing_analyzer(self, analyzer_class: type) -> Any:
        """Instantiate a hashing analyzer with preferred constructor."""
        try:
            return analyzer_class(self.filename, self.adapter._r2)
        except TypeError:
            return analyzer_class(self.adapter._r2, self.filename)

    def _run_hashing_analyzer(self, name: str, analyzer: Any) -> Any:
        """Run analyzer with richer method when available."""
        if name == "tlsh" and hasattr(analyzer, "analyze_sections"):
            return analyzer.analyze_sections()
        if name == "ccbhash" and hasattr(analyzer, "analyze_functions"):
            return analyzer.analyze_functions()
        if name == "simhash" and hasattr(analyzer, "analyze_detailed"):
            return analyzer.analyze_detailed()
        return analyzer.analyze()

    def _store_hashing_result(
        self, context: dict[str, Any], results: dict[str, Any], name: str, result: Any
    ) -> None:
        """Store hashing analyzer results."""
        context["results"][name] = result
        results[name] = result


class DetectionStage(AnalysisStage):
    """
    Execute detection analyzers for patterns and signatures.

    Runs detection analyzers including:
        - Packer detection
        - Cryptographic constant detection
        - Anti-analysis technique detection
        - Compiler detection
        - YARA rule matching
    """

    def __init__(
        self,
        registry: AnalyzerRegistry,
        adapter: R2PipeAdapter,
        config,
        filename: str,
        options: dict[str, Any],
    ):
        """
        Initialize detection stage.

        Args:
            registry: Analyzer registry for dynamic analyzer lookup
            adapter: R2Pipe adapter for radare2 operations
            config: Configuration object
            filename: Path to file being analyzed
            options: Analysis options controlling which detections to run
        """
        super().__init__(
            name="detection",
            description="Pattern and signature detection",
            optional=True,
            dependencies=["format_detection"],
        )
        self.registry = registry
        self.adapter = adapter
        self.config = config
        self.filename = filename
        self.options = options

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        """Execute detection analyzers."""
        results: dict[str, Any] = {}
        # Packer detection
        if self.options.get("detect_packer", True):
            res = self._run_packer_detection(context)
            if res is not None:
                results.update(res)

        # Crypto detection
        if self.options.get("detect_crypto", True):
            res = self._run_crypto_detection(context)
            if res is not None:
                results.update(res)

        # Anti-analysis detection
        res = self._run_anti_analysis_detection(context)
        if res is not None:
            results.update(res)

        # Compiler detection
        res = self._run_compiler_detection(context)
        if res is not None:
            results.update(res)

        # YARA scanning
        res = self._run_yara_analysis(context)
        if res is not None:
            results.update(res)

        return results

    def _run_analyzer(
        self, context: dict[str, Any], analyzer_name: str, result_key: str
    ) -> dict[str, Any] | None:
        """Helper to run a single analyzer."""
        analyzer_class = self.registry.get_analyzer_class(analyzer_name)
        if analyzer_class:
            try:
                analyzer = analyzer_class(self.adapter._r2, self.config)
                data = analyzer.detect()
                context["results"][result_key] = data
                return {result_key: data}
            except Exception as e:
                logger.warning(f"Analyzer '{analyzer_name}' failed: {e}")
                context["results"][result_key] = {"error": str(e)}
                return {result_key: {"error": str(e)}}
        return None

    def _run_packer_detection(self, context: dict[str, Any]) -> dict[str, Any] | None:
        """Run packer detection."""
        return self._run_analyzer(context, "packer_detector", "packer")

    def _run_crypto_detection(self, context: dict[str, Any]) -> dict[str, Any] | None:
        """Run crypto detection."""
        return self._run_analyzer(context, "crypto_analyzer", "crypto")

    def _run_anti_analysis_detection(self, context: dict[str, Any]) -> dict[str, Any] | None:
        """Run anti-analysis detection."""
        return self._run_analyzer(context, "anti_analysis", "anti_analysis")

    def _run_compiler_detection(self, context: dict[str, Any]) -> dict[str, Any] | None:
        """Run compiler detection."""
        analyzer_class = self.registry.get_analyzer_class("compiler_detector")
        if analyzer_class:
            try:
                analyzer = analyzer_class(self.adapter._r2, self.config)
                data = analyzer.detect_compiler()
                context["results"]["compiler"] = data
                return {"compiler": data}
            except Exception as e:
                logger.warning(f"Compiler detection failed: {e}")
                context["results"]["compiler"] = {"error": str(e)}
                return {"compiler": {"error": str(e)}}
        return None

    def _run_yara_analysis(self, context: dict[str, Any]) -> dict[str, Any] | None:
        """Run YARA analysis."""
        analyzer_class = self.registry.get_analyzer_class("yara_analyzer")
        if analyzer_class:
            try:
                analyzer = analyzer_class(self.adapter._r2, self.config, self.filename)
                custom_rules = self.options.get("custom_yara")
                data = analyzer.scan(custom_rules)
                context["results"]["yara_matches"] = data
                return {"yara_matches": data}
            except Exception as e:
                logger.warning(f"YARA analysis failed: {e}")
                context["results"]["yara_matches"] = []
                return {"yara_matches": []}
        return None


class SecurityStage(AnalysisStage):
    """
    Analyze security features and exploit mitigations.

    Examines security-related aspects:
        - Exploit mitigations (DEP, ASLR, CFG, etc.)
        - Authenticode signatures (PE files)
        - Security features from format analyzers
    """

    def __init__(self, registry: AnalyzerRegistry, adapter: R2PipeAdapter, config, filename: str):
        """
        Initialize security stage.

        Args:
            registry: Analyzer registry for dynamic analyzer lookup
            adapter: R2Pipe adapter for radare2 operations
            config: Configuration object
            filename: Path to file being analyzed
        """
        super().__init__(
            name="security",
            description="Security feature and mitigation analysis",
            optional=True,
            dependencies=["format_detection"],
        )
        self.registry = registry
        self.adapter = adapter
        self.config = config
        self.filename = filename

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        """Execute security analysis."""
        # Get PE security features if PE format
        file_format = context.get("metadata", {}).get("file_format", "Unknown")

        results: dict[str, Any] = {}
        if file_format == "PE":
            res = self._analyze_pe_security(context)
            if res is not None:
                results.update(res)

        # Run exploit mitigation analyzer
        res = self._analyze_mitigations(context)
        if res is not None:
            results.update(res)

        return results

    def _analyze_pe_security(self, context: dict[str, Any]) -> dict[str, Any] | None:
        """Analyze PE security features."""
        pe_analyzer_class = self.registry.get_analyzer_class("pe_analyzer")
        if pe_analyzer_class:
            try:
                analyzer = pe_analyzer_class(self.adapter._r2, self.config, self.filename)
                data = analyzer.get_security_features()
                context["results"]["security"] = data
                return {"security": data}
            except Exception as e:
                logger.warning(f"PE security analysis failed: {e}")
                context["results"]["security"] = {"error": str(e)}
                return {"security": {"error": str(e)}}
        return None

    def _analyze_mitigations(self, context: dict[str, Any]) -> dict[str, Any] | None:
        """Analyze exploit mitigations."""
        mitigation_class = self.registry.get_analyzer_class("exploit_mitigation")
        if mitigation_class:
            try:
                analyzer = mitigation_class(self.adapter._r2, self.config)
                mitigations = analyzer.analyze()
                # Merge with existing security results
                if "security" in context["results"]:
                    context["results"]["security"].update(mitigations)
                else:
                    context["results"]["security"] = mitigations
            except Exception as e:
                logger.debug(f"Mitigation analysis failed: {e}")
                return None
            return {"security": context["results"].get("security", {})}
        return None


class MetadataStage(AnalysisStage):
    """
    Extract structural metadata from binary.

    Analyzes:
        - Sections and segments
        - Import table
        - Export table
        - Strings
        - Functions (if analysis option enabled)
    """

    def __init__(
        self,
        registry: AnalyzerRegistry,
        adapter: R2PipeAdapter,
        config,
        filename: str,
        options: dict[str, Any],
    ):
        """
        Initialize metadata stage.

        Args:
            registry: Analyzer registry for dynamic analyzer lookup
            adapter: R2Pipe adapter for radare2 operations
            config: Configuration object
            filename: Path to file being analyzed
            options: Analysis options
        """
        super().__init__(
            name="metadata",
            description="Structural metadata extraction",
            optional=True,
            dependencies=["file_info", "format_detection"],
        )
        self.registry = registry
        self.adapter = adapter
        self.config = config
        self.filename = filename
        self.options = options

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        """Execute metadata extraction."""
        results: dict[str, Any] = {}
        # Sections
        res = self._extract_sections(context)
        if res is not None:
            results.update(res)

        # Imports
        res = self._extract_imports(context)
        if res is not None:
            results.update(res)

        # Exports
        res = self._extract_exports(context)
        if res is not None:
            results.update(res)

        # Strings
        res = self._extract_strings(context)
        if res is not None:
            results.update(res)

        # Functions (optional)
        if self.options.get("analyze_functions", True):
            res = self._extract_functions(context)
            if res is not None:
                results.update(res)

        return results

    def _run_analyzer_method(
        self,
        context: dict[str, Any],
        analyzer_name: str,
        method_name: str,
        result_key: str,
        default_value: list | dict | None = None,
    ) -> dict[str, Any] | None:
        """Generic helper to run an analyzer method and store results."""
        if default_value is None:
            default_value = []

        analyzer_class = self.registry.get_analyzer_class(analyzer_name)
        if not analyzer_class:
            return None

        try:
            analyzer = analyzer_class(self.adapter._r2, self.config)
            method = getattr(analyzer, method_name)
            data = method()
            context["results"][result_key] = data
            return {result_key: data}
        except Exception as e:
            logger.warning(f"{result_key.replace('_', ' ').title()} analysis failed: {e}")
            context["results"][result_key] = default_value
            return {result_key: default_value}

    def _extract_sections(self, context: dict[str, Any]) -> dict[str, Any] | None:
        """Extract section information."""
        return self._run_analyzer_method(
            context, "section_analyzer", "analyze_sections", "sections"
        )

    def _extract_imports(self, context: dict[str, Any]) -> dict[str, Any] | None:
        """Extract import information."""
        return self._run_analyzer_method(context, "import_analyzer", "get_imports", "imports")

    def _extract_exports(self, context: dict[str, Any]) -> dict[str, Any] | None:
        """Extract export information."""
        return self._run_analyzer_method(context, "export_analyzer", "get_exports", "exports")

    def _extract_strings(self, context: dict[str, Any]) -> dict[str, Any] | None:
        """Extract strings."""
        return self._run_analyzer_method(context, "string_analyzer", "extract_strings", "strings")

    def _extract_functions(self, context: dict[str, Any]) -> dict[str, Any] | None:
        """Extract function information."""
        return self._run_analyzer_method(
            context, "function_analyzer", "analyze_functions", "functions", {}
        )


class AnalyzerStage(AnalysisStage):
    """
    Generic stage for executing a single analyzer.

    This stage provides a flexible wrapper for running any registered
    analyzer dynamically. Useful for custom pipeline configurations.
    """

    def __init__(
        self,
        name: str,
        analyzer_class: type,
        adapter: R2PipeAdapter,
        config,
        filename: str,
        result_key: str | None = None,
        optional: bool = True,
    ):
        """
        Initialize generic analyzer stage.

        Args:
            name: Stage name
            analyzer_class: Analyzer class to instantiate
            adapter: R2Pipe adapter
            config: Configuration object
            filename: Path to file
            result_key: Key for storing results (defaults to name)
            optional: Whether stage is optional
        """
        super().__init__(
            name=name,
            description=f"Execute {analyzer_class.__name__}",
            optional=optional,
        )
        self.analyzer_class = analyzer_class
        self.adapter = adapter
        self.config = config
        self.filename = filename
        self.result_key = result_key or name

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        """Execute the analyzer."""
        try:
            # Try different initialization signatures
            try:
                analyzer = self.analyzer_class(self.adapter._r2, self.config, self.filename)
            except TypeError:
                try:
                    analyzer = self.analyzer_class(self.adapter._r2, self.config)
                except TypeError:
                    analyzer = self.analyzer_class(self.adapter._r2, self.filename)

            # Try different analysis methods
            if hasattr(analyzer, "analyze"):
                result = analyzer.analyze()
            elif hasattr(analyzer, "detect"):
                result = analyzer.detect()
            elif hasattr(analyzer, "scan"):
                result = analyzer.scan()
            else:
                logger.warning(
                    f"Analyzer {self.analyzer_class.__name__} has no analyze/detect/scan method"
                )
                result = {"error": "No suitable analysis method found"}

            context["results"][self.result_key] = result

        except Exception as e:
            logger.warning(f"Analyzer {self.analyzer_class.__name__} failed: {e}")
            context["results"][self.result_key] = {"error": str(e)}

        return context


class IndicatorStage(AnalysisStage):
    """
    Generate suspicious indicators from analysis results.

    Analyzes all accumulated results to identify suspicious patterns:
        - Packed binaries
        - Anti-analysis techniques
        - Suspicious API imports
        - YARA rule matches
    """

    def __init__(self):
        """Initialize indicator generation stage."""
        super().__init__(
            name="indicators",
            description="Generate suspicious indicators",
            optional=True,
            dependencies=["metadata", "detection"],
        )

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        """Generate indicators from results."""
        indicators = []
        results = context["results"]

        # Check for packed files
        packer = results.get("packer", {})
        if packer.get("is_packed"):
            indicators.append(
                {
                    "type": "Packer",
                    "description": f"File appears to be packed with {packer.get('packer_type', 'Unknown')}",
                    "severity": "Medium",
                }
            )

        # Check for anti-analysis
        anti_analysis = results.get("anti_analysis", {})
        if anti_analysis.get("anti_debug"):
            indicators.append(
                {
                    "type": "Anti-Debug",
                    "description": "Anti-debugging techniques detected",
                    "severity": "High",
                }
            )

        if anti_analysis.get("anti_vm"):
            indicators.append(
                {
                    "type": "Anti-VM",
                    "description": "Anti-virtualization techniques detected",
                    "severity": "High",
                }
            )

        # Check for suspicious imports
        imports = results.get("imports", [])
        suspicious_apis = [
            "VirtualAlloc",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "SetThreadContext",
        ]
        for imp in imports:
            if imp.get("name") in suspicious_apis:
                indicators.append(
                    {
                        "type": "Suspicious API",
                        "description": f"Suspicious API call: {imp.get('name')}",
                        "severity": "Medium",
                    }
                )

        # Check YARA matches
        yara_matches = results.get("yara_matches", [])
        for match in yara_matches:
            indicators.append(
                {
                    "type": "YARA Match",
                    "description": f"YARA rule matched: {match.get('rule', 'Unknown')}",
                    "severity": "High",
                }
            )

        context["results"]["indicators"] = indicators
        return {"indicators": indicators}
