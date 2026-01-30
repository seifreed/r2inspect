#!/usr/bin/env python3
"""
r2inspect Core Inspector - Main analysis engine using Pipeline and Registry patterns

This module provides the R2Inspector facade class that orchestrates binary analysis
using a pipeline-based architecture with dynamic analyzer registration.

Architecture:
    - Pipeline Pattern: Sequential execution of analysis stages
    - Registry Pattern: Dynamic analyzer discovery and instantiation
    - Adapter Pattern: Uniform interface to r2pipe backend
    - Facade Pattern: Simplified API for complex subsystems
    - Composition: Delegates to FileValidator, R2Session, PipelineBuilder, ResultAggregator

Copyright (C) 2025 Marc Rivero Lopez
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

import warnings
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from ..adapters.r2pipe_adapter import R2PipeAdapter
from ..config import Config
from ..pipeline.stages import FileInfoStage, FormatDetectionStage
from ..registry.default_registry import create_default_registry
from ..utils.error_handler import ErrorCategory, ErrorSeverity, error_handler
from ..utils.logger import get_logger
from ..utils.memory_manager import MemoryAwareAnalyzer, global_memory_monitor
from .file_validator import FileValidator
from .pipeline_builder import PipelineBuilder
from .r2_session import R2Session
from .result_aggregator import ResultAggregator

logger = get_logger(__name__)


class R2Inspector(MemoryAwareAnalyzer):
    """
    Main analysis facade using Pipeline and Registry patterns.

    This class serves as the primary entry point for binary analysis, providing
    a high-level API that orchestrates complex analysis workflows through a
    pipeline-based architecture.

    The refactored design provides:
        - Dynamic analyzer discovery via Registry pattern
        - Flexible analysis workflows via Pipeline pattern
        - Consistent r2pipe interface via Adapter pattern
        - Backward-compatible API with legacy code
        - Composition with FileValidator, R2Session, PipelineBuilder, ResultAggregator

    Attributes:
        filename: Path to file being analyzed
        config: Configuration object
        verbose: Verbose logging flag
        registry: Analyzer registry for dynamic discovery
        adapter: R2Pipe adapter for radare2 operations
        r2: Raw r2pipe instance (for backward compatibility)
        file_path: Pathlib Path object for file
    """

    def __init__(self, filename: str, config: Config | None = None, verbose: bool = False):
        """
        Initialize R2Inspector with file and configuration.

        Args:
            filename: Path to binary file to analyze
            config: Configuration object (uses default if None)
            verbose: Enable verbose logging

        Raises:
            ValueError: If file validation fails
            RuntimeError: If r2pipe initialization fails
        """
        logger.debug(f"R2Inspector.__init__ called with filename: {filename}")
        super().__init__(global_memory_monitor)

        self.filename = filename
        self.config = config or Config()
        self.verbose = verbose
        self.r2: Any = None
        self.adapter: Any = None
        self.registry: Any = None
        self.file_path = Path(filename)

        # Initialize component classes
        self._file_validator = FileValidator(filename)
        self._r2_session = R2Session(filename)
        self._result_aggregator = ResultAggregator()
        self._pipeline_builder: Any = None  # Initialized after adapter/registry

        logger.debug(f"Starting file validation for: {filename}")
        # Validate file before proceeding
        if not self._file_validator.validate():
            logger.error(f"File validation failed for: {filename}")
            raise ValueError(f"File validation failed: {filename}")
        logger.debug("File validation passed")

        logger.debug("Starting r2pipe initialization")
        # Initialize r2pipe via R2Session
        self._init_r2pipe()
        logger.debug("r2pipe initialization completed")

        logger.debug("Starting adapter and registry initialization")
        # Initialize adapter and registry (replaces _init_analyzers)
        self._init_infrastructure()
        logger.debug("Infrastructure initialized successfully")

    @property
    def _cleanup_required(self) -> bool:
        """Check if cleanup is required."""
        return self._r2_session._cleanup_required

    @_cleanup_required.setter
    def _cleanup_required(self, value: bool):
        """Set cleanup required flag."""
        self._r2_session._cleanup_required = value

    @error_handler(
        category=ErrorCategory.R2PIPE,
        severity=ErrorSeverity.CRITICAL,
        context={"phase": "initialization"},
        fallback_result=None,
    )
    def _init_r2pipe(self):
        """Initialize r2pipe connection via R2Session."""
        file_size_mb = self._file_validator._file_size_mb()
        self.r2 = self._r2_session.open(file_size_mb)

    def _init_infrastructure(self):
        """
        Initialize adapter and registry infrastructure.

        Replaces the old _init_analyzers() method with a registry-based approach.
        Analyzers are no longer instantiated eagerly; instead, they are discovered
        dynamically via the registry at execution time.

        This reduces initialization overhead and improves modularity.
        """
        # Initialize R2Pipe adapter
        self.adapter = R2PipeAdapter(self.r2)
        logger.debug("R2Pipe adapter initialized")

        # Initialize analyzer registry with default configuration
        self.registry = create_default_registry()
        logger.debug(f"Analyzer registry initialized with {len(self.registry)} analyzers")

        # Initialize pipeline builder with dependencies
        self._pipeline_builder = PipelineBuilder(
            self.adapter, self.registry, self.config, self.filename
        )

        # Log registered analyzers for debugging
        if self.verbose:
            for analyzer_info in self.registry.list_analyzers():
                logger.debug(
                    f"Registered: {analyzer_info['name']} "
                    f"({analyzer_info['category']}, "
                    f"formats: {analyzer_info['file_formats']})"
                )

    def _cleanup(self):
        """Clean up r2pipe instance via R2Session."""
        self._r2_session.close()
        self.r2 = None

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup"""
        self._cleanup()
        return False

    def __del__(self):
        """Destructor with cleanup"""
        if hasattr(self, "_r2_session") and self._r2_session._cleanup_required:
            self._cleanup()

    @error_handler(
        category=ErrorCategory.ANALYSIS,
        severity=ErrorSeverity.CRITICAL,
        context={"phase": "main_analysis"},
        fallback_result={"error": "Analysis failed"},
    )
    def analyze(
        self,
        progress_callback: Callable[[str], None] | None = None,
        **options,
    ) -> dict[str, Any]:
        """
        Perform complete binary analysis using pipeline architecture.

        This method orchestrates the analysis workflow by:
            1. Building an analysis pipeline based on options
            2. Executing the pipeline with optional progress tracking
            3. Collecting memory statistics
            4. Handling errors gracefully

        Args:
            progress_callback: Optional callback function that receives stage names
                for progress tracking. The CLI layer can provide a Rich-based
                callback for visual progress display.
            **options: Analysis options including:
                - batch_mode: Disable progress display
                - detect_packer: Enable packer detection
                - detect_crypto: Enable crypto detection
                - analyze_functions: Enable function analysis
                - custom_yara: Path to custom YARA rules

        Returns:
            Dictionary containing:
                - results: Analysis results from all stages
                - memory_stats: Memory usage statistics
                - errors: Any errors encountered (optional)

        Raises:
            MemoryError: If memory limits are exceeded
            Exception: Propagates critical errors from required stages
        """
        # Check initial memory state
        initial_memory = self.memory_monitor.check_memory(force=True)
        logger.debug(
            f"Starting analysis with {initial_memory['process_memory_mb']:.1f}MB memory usage"
        )

        try:
            # Build analysis pipeline using PipelineBuilder
            pipeline = self._pipeline_builder.build(options)

            # Determine parallel execution from configuration
            use_parallel = bool(self.config.get("pipeline", "parallel_execution", True))

            # Execute with progress callback if provided and not parallel
            if progress_callback and not use_parallel:
                results = self._execute_with_progress(pipeline, options, progress_callback)
            else:
                results = self._execute_without_progress(pipeline, options, parallel=use_parallel)

            # Add memory statistics
            final_memory = self.memory_monitor.check_memory(force=True)
            results["memory_stats"] = {
                "initial_memory_mb": initial_memory["process_memory_mb"],
                "final_memory_mb": final_memory["process_memory_mb"],
                "memory_used_mb": final_memory["process_memory_mb"]
                - initial_memory["process_memory_mb"],
                "peak_memory_mb": final_memory.get("peak_memory_mb", 0),
                "gc_count": final_memory.get("gc_count", 0),
            }

            return results

        except MemoryError:
            logger.error("Analysis failed due to memory constraints")
            self.memory_monitor._trigger_gc(aggressive=True)
            return {
                "error": "Memory limit exceeded",
                "memory_stats": self.memory_monitor.check_memory(force=True),
            }

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return {
                "error": str(e),
                "memory_stats": self.memory_monitor.check_memory(force=True),
            }

    def _execute_with_progress(
        self,
        pipeline,
        options: dict[str, Any],
        progress_callback: Callable[[str], None],
    ) -> dict[str, Any]:
        """
        Execute pipeline with progress callback.

        Args:
            pipeline: Configured pipeline to execute
            options: Analysis options
            progress_callback: Callback function that receives stage names
                for progress tracking

        Returns:
            Analysis results dictionary
        """
        # Execute pipeline with progress callback (sequential)
        return self._as_dict(pipeline.execute_with_progress(progress_callback, options))

    def _execute_without_progress(
        self,
        pipeline,
        options: dict[str, Any],
        parallel: bool = False,
    ) -> dict[str, Any]:
        """
        Execute pipeline without progress display (batch mode).

        Args:
            pipeline: Configured pipeline to execute
            options: Analysis options
            parallel: Whether to execute stages in parallel

        Returns:
            Analysis results dictionary
        """
        return self._as_dict(pipeline.execute(options, parallel=parallel))

    @staticmethod
    def _as_dict(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _as_bool_dict(value: Any) -> dict[str, bool]:
        if isinstance(value, dict):
            return {str(key): bool(val) for key, val in value.items()}
        return {}

    @staticmethod
    def _as_str(value: Any, default: str = "") -> str:
        return value if isinstance(value, str) else default

    # =========================================================================
    # Backward-Compatible API Methods
    #
    # These methods maintain compatibility with legacy code by delegating to
    # the registry-based analyzers. They are thin wrappers that instantiate
    # analyzers on-demand rather than storing them as instance variables.
    # =========================================================================

    def _execute_analyzer(
        self, analyzer_name: str, method_name: str = "analyze", *args, **kwargs
    ) -> Any:
        """
        Generic helper to execute any analyzer from the registry.

        This method eliminates code duplication by providing a single point
        of execution for all registry-based analyzers.

        Args:
            analyzer_name: Name of analyzer in registry (e.g., "ssdeep", "pe_analyzer")
            method_name: Method to call on analyzer instance (default: "analyze")
            *args: Positional arguments to pass to analyzer method
            **kwargs: Keyword arguments to pass to analyzer method

        Returns:
            Result from analyzer method, or empty dict/list based on return type
            annotation if analyzer not found
        """
        analyzer_class = self.registry.get_analyzer_class(analyzer_name)

        if not analyzer_class:
            logger.debug(f"Analyzer '{analyzer_name}' not found in registry")
            return {}

        try:
            # Introspect constructor to determine required arguments
            import inspect

            sig = inspect.signature(analyzer_class.__init__)
            params = list(sig.parameters.keys())[1:]  # Skip 'self'

            # Build constructor arguments dynamically based on signature
            ctor_args = []
            if "r2" in params or "r2pipe" in params:
                ctor_args.append(self.r2)
            if "config" in params:
                ctor_args.append(self.config)
            if "filename" in params or "file_path" in params:
                ctor_args.append(self.filename)

            # Instantiate analyzer
            analyzer = analyzer_class(*ctor_args)

            # Get and invoke the requested method
            method = getattr(analyzer, method_name, None)
            if not method:
                logger.warning(f"Method '{method_name}' not found on analyzer '{analyzer_name}'")
                return {}

            # Invoke method with provided arguments
            return method(*args, **kwargs)

        except Exception as e:
            logger.error(f"Error executing {analyzer_name}.{method_name}(): {e}", exc_info=True)
            return {}

    @error_handler(
        category=ErrorCategory.FILE_ACCESS,
        severity=ErrorSeverity.HIGH,
        context={"analysis_type": "file_info"},
        fallback_result={},
    )
    def get_file_info(self) -> dict[str, Any]:
        """
        Get basic file information.

        Returns:
            Dictionary containing file metadata
        """
        stage = FileInfoStage(self.adapter, self.filename)
        context: dict[str, Any] = {"options": {}, "results": {}}
        result_context = stage.execute(context)
        return self._as_dict(cast(dict[str, Any], result_context["results"]).get("file_info"))

    def _detect_file_format(self) -> str:
        """
        Detect the binary file format.

        Returns:
            Format string (PE/ELF/Mach-O/Unknown)
        """
        stage = FormatDetectionStage(self.adapter, self.filename)
        context: dict[str, Any] = {"options": {}, "results": {}, "metadata": {}}
        result_context = stage.execute(context)
        metadata = cast(dict[str, Any], result_context.get("metadata", {}))
        return self._as_str(metadata.get("file_format"), "Unknown")

    def get_pe_info(self) -> dict[str, Any]:
        """Get PE-specific information.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "get_pe_info() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('pe_analyzer') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._as_dict(self._execute_analyzer("pe_analyzer"))

    def get_elf_info(self) -> dict[str, Any]:
        """Get ELF-specific information.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "get_elf_info() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('elf_analyzer') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._as_dict(self._execute_analyzer("elf_analyzer"))

    def get_macho_info(self) -> dict[str, Any]:
        """Get Mach-O-specific information.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "get_macho_info() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('macho_analyzer') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._as_dict(self._execute_analyzer("macho_analyzer"))

    def get_strings(self) -> list[str]:
        """Extract strings from binary.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "get_strings() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('string_analyzer') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        result = self._execute_analyzer("string_analyzer", "extract_strings")
        return result if isinstance(result, list) else []

    def get_security_features(self) -> dict[str, bool]:
        """Check security features.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "get_security_features() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('pe_analyzer') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._as_bool_dict(self._execute_analyzer("pe_analyzer", "get_security_features"))

    def get_imports(self) -> list[dict[str, Any]]:
        """Get imported functions.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "get_imports() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('import_analyzer') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        result = self._execute_analyzer("import_analyzer", "get_imports")
        return result if isinstance(result, list) else []

    def get_exports(self) -> list[dict[str, Any]]:
        """Get exported functions.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "get_exports() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('export_analyzer') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        result = self._execute_analyzer("export_analyzer", "get_exports")
        return result if isinstance(result, list) else []

    def get_sections(self) -> list[dict[str, Any]]:
        """Get section information.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "get_sections() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('section_analyzer') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        result = self._execute_analyzer("section_analyzer", "analyze_sections")
        return result if isinstance(result, list) else []

    def detect_packer(self) -> dict[str, Any]:
        """Detect packers.

        .. deprecated:: 2.0
            Use `analyze(detect_packer=True)` instead, or access via registry directly.
        """
        warnings.warn(
            "detect_packer() is deprecated. Use analyze(detect_packer=True) or "
            "registry.get_analyzer_class('packer_detector') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._as_dict(self._execute_analyzer("packer_detector", "detect"))

    @error_handler(
        category=ErrorCategory.ANALYSIS,
        severity=ErrorSeverity.MEDIUM,
        context={"analysis_type": "crypto_detection"},
        fallback_result={
            "algorithms": [],
            "constants": [],
            "error": "Crypto detection failed",
        },
    )
    def detect_crypto(self) -> dict[str, Any]:
        """Detect cryptographic patterns.

        .. deprecated:: 2.0
            Use `analyze(detect_crypto=True)` instead, or access via registry directly.
        """
        warnings.warn(
            "detect_crypto() is deprecated. Use analyze(detect_crypto=True) or "
            "registry.get_analyzer_class('crypto_analyzer') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        result = self._execute_analyzer("crypto_analyzer", "detect")
        if not result:
            return {"algorithms": [], "constants": [], "error": "Analyzer not found"}
        return self._as_dict(result)

    def detect_anti_analysis(self) -> dict[str, Any]:
        """Detect anti-analysis techniques.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "detect_anti_analysis() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('anti_analysis') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._as_dict(self._execute_analyzer("anti_analysis", "detect"))

    def detect_compiler(self) -> dict[str, Any]:
        """Detect compiler information.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "detect_compiler() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('compiler_detector') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._as_dict(self._execute_analyzer("compiler_detector", "detect_compiler"))

    def run_yara_rules(self, custom_rules_path: str | None = None) -> list[dict[str, Any]]:
        """Run YARA rules against the file.

        .. deprecated:: 2.0
            Use `analyze(custom_yara=path)` instead, or access via registry directly.
        """
        warnings.warn(
            "run_yara_rules() is deprecated. Use analyze(custom_yara=path) or "
            "registry.get_analyzer_class('yara_analyzer') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        result = self._execute_analyzer("yara_analyzer", "scan", custom_rules_path)
        return result if isinstance(result, list) else []

    def search_xor(self, search_string: str) -> list[dict[str, Any]]:
        """Search for XOR'd strings.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "search_xor() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('string_analyzer') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        result = self._execute_analyzer("string_analyzer", "search_xor", search_string)
        return result if isinstance(result, list) else []

    def generate_indicators(self, analysis_results: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Generate suspicious indicators based on analysis results.

        Delegates to ResultAggregator.

        Args:
            analysis_results: Dictionary containing all analysis results

        Returns:
            List of indicator dictionaries with type, description, and severity
        """
        return self._result_aggregator.generate_indicators(analysis_results)

    def analyze_functions(self) -> dict[str, Any]:
        """Perform function analysis including MACHOC hashing.

        .. deprecated:: 2.0
            Use `analyze(analyze_functions=True)` instead, or access via registry directly.
        """
        warnings.warn(
            "analyze_functions() is deprecated. Use analyze(analyze_functions=True) or "
            "registry.get_analyzer_class('function_analyzer') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._as_dict(self._execute_analyzer("function_analyzer", "analyze_functions"))

    def analyze_ssdeep(self) -> dict[str, Any]:
        """Perform SSDeep fuzzy hashing analysis.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "analyze_ssdeep() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('ssdeep') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._as_dict(self._execute_analyzer("ssdeep"))

    def analyze_tlsh(self) -> dict[str, Any]:
        """Perform TLSH locality sensitive hashing analysis.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "analyze_tlsh() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('tlsh') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._as_dict(self._execute_analyzer("tlsh"))

    def analyze_telfhash(self) -> dict[str, Any]:
        """Perform telfhash analysis for ELF files.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "analyze_telfhash() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('telfhash') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._as_dict(self._execute_analyzer("telfhash"))

    def analyze_rich_header(self) -> dict[str, Any]:
        """Perform Rich Header analysis for PE files.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "analyze_rich_header() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('rich_header') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._as_dict(self._execute_analyzer("rich_header"))

    def analyze_impfuzzy(self) -> dict[str, Any]:
        """Perform impfuzzy analysis for PE files.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "analyze_impfuzzy() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('impfuzzy') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._as_dict(self._execute_analyzer("impfuzzy"))

    def analyze_ccbhash(self) -> dict[str, Any]:
        """Perform CCBHash (Control Flow Graph Hash) analysis.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "analyze_ccbhash() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('ccbhash') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._as_dict(self._execute_analyzer("ccbhash"))

    def analyze_binlex(self) -> dict[str, Any]:
        """Perform Binlex (N-gram lexical analysis) analysis.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "analyze_binlex() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('binlex') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._as_dict(self._execute_analyzer("binlex"))

    def analyze_binbloom(self) -> dict[str, Any]:
        """Perform Binbloom (Bloom filter) analysis.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "analyze_binbloom() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('binbloom') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._as_dict(self._execute_analyzer("binbloom"))

    def analyze_simhash(self) -> dict[str, Any]:
        """Perform SimHash (similarity hashing) analysis.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "analyze_simhash() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('simhash') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._as_dict(self._execute_analyzer("simhash"))

    def analyze_bindiff(self) -> dict[str, Any]:
        """Perform BinDiff (comparison features) analysis.

        .. deprecated:: 2.0
            Use `analyze()` with options instead, or access via registry directly.
        """
        warnings.warn(
            "analyze_bindiff() is deprecated. Use analyze() or "
            "registry.get_analyzer_class('bindiff') instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._as_dict(self._execute_analyzer("bindiff"))

    def generate_executive_summary(self, analysis_results: dict[str, Any]) -> dict[str, Any]:
        """
        Generate executive summary for quick consumption.

        Delegates to ResultAggregator.

        Args:
            analysis_results: Dictionary containing all analysis results

        Returns:
            Dictionary containing structured summary
        """
        return self._result_aggregator.generate_executive_summary(analysis_results)

    def close(self):
        """Close r2pipe connection"""
        if self.r2:
            self.r2.quit()


__all__ = ["R2Inspector"]
