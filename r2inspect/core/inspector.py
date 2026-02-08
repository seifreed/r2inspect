#!/usr/bin/env python3
"""Core inspector orchestrating analysis via pipeline and registry."""

from collections.abc import Callable
from pathlib import Path
from types import TracebackType
from typing import Any, Literal

from ..interfaces import ConfigLike, FileValidatorLike, MemoryMonitorLike, ResultAggregatorLike
from ..utils.error_handler import ErrorCategory, ErrorSeverity, error_handler
from ..utils.logger import get_logger
from ..utils.memory_manager import MemoryAwareAnalyzer
from .inspector_helpers import InspectorExecutionMixin

logger = get_logger(__name__)


class R2Inspector(InspectorExecutionMixin, MemoryAwareAnalyzer):
    """Main analysis facade using pipeline and registry."""

    def __init__(
        self,
        filename: str,
        config: ConfigLike | None = None,
        verbose: bool = False,
        *,
        cleanup_callback: Callable[[], None] | None = None,
        adapter: Any | None = None,
        registry_factory: Callable[[], Any] | None = None,
        pipeline_builder_factory: Callable[[Any, Any, ConfigLike, str], Any] | None = None,
        config_factory: Callable[[], ConfigLike] | None = None,
        file_validator_factory: Callable[[str], FileValidatorLike] | None = None,
        result_aggregator_factory: Callable[[], ResultAggregatorLike] | None = None,
        memory_monitor: MemoryMonitorLike | None = None,
    ):
        """
        Initialize R2Inspector with file and configuration.

        Args:
            filename: Path to binary file to analyze
            config: Configuration object (uses default if None)
            verbose: Enable verbose logging

        Raises:
            ValueError: If file validation fails
        """
        logger.debug(f"R2Inspector.__init__ called with filename: {filename}")
        if memory_monitor is None:
            raise ValueError("memory_monitor must be provided")
        super().__init__(memory_monitor)

        self.filename = filename
        if config is None:
            if config_factory is None:
                raise ValueError("config_factory must be provided when config is None")
            self.config = config_factory()
        else:
            self.config = config
        self.verbose = verbose
        if adapter is None:
            raise ValueError("adapter must be provided")
        self.adapter: Any = adapter
        self.registry: Any | None = None
        self.file_path = Path(filename)
        self._cleanup_callback = cleanup_callback
        self._registry_factory = registry_factory
        self._pipeline_builder_factory = pipeline_builder_factory
        self._pipeline_builder: Any | None = None
        self._file_validator_factory = file_validator_factory
        self._result_aggregator_factory = result_aggregator_factory

        # Initialize component classes
        if self._file_validator_factory is None or self._result_aggregator_factory is None:
            raise ValueError(
                "file_validator_factory and result_aggregator_factory must be provided"
            )
        self._file_validator = self._file_validator_factory(filename)
        self._result_aggregator = self._result_aggregator_factory()

        logger.debug(f"Starting file validation for: {filename}")
        # Validate file before proceeding
        if not self._file_validator.validate():
            logger.error(f"File validation failed for: {filename}")
            raise ValueError(f"File validation failed: {filename}")
        logger.debug("File validation passed")

        logger.debug("Starting adapter and registry initialization")
        # Validate adapter/registry/pipeline builder
        if self._registry_factory is None or self._pipeline_builder_factory is None:
            raise ValueError("registry_factory and pipeline_builder_factory must be provided")

        # Initialize adapter and registry (replaces _init_analyzers)
        self._init_infrastructure()
        logger.debug("Infrastructure initialized successfully")

    def _init_infrastructure(self) -> None:
        """
        Initialize adapter and registry infrastructure.

        Replaces the old _init_analyzers() method with a registry-based approach.
        Analyzers are no longer instantiated eagerly; instead, they are discovered
        dynamically via the registry at execution time.

        This reduces initialization overhead and improves modularity.
        """
        if self._registry_factory is None or self._pipeline_builder_factory is None:
            raise ValueError("registry_factory and pipeline_builder_factory must be provided")
        self.registry = self._registry_factory()
        self._pipeline_builder = self._pipeline_builder_factory(
            self.adapter, self.registry, self.config, self.filename
        )

        logger.debug("R2Pipe adapter initialized")
        logger.debug(f"Analyzer registry initialized with {len(self.registry)} analyzers")

        # Log registered analyzers for debugging
        if self.verbose:
            for analyzer_info in self.registry.list_analyzers():
                logger.debug(
                    f"Registered: {analyzer_info['name']} "
                    f"({analyzer_info['category']}, "
                    f"formats: {analyzer_info['file_formats']})"
                )

    def _cleanup(self) -> None:
        """Clean up r2 resources via callback."""
        if self._cleanup_callback is not None:
            self._cleanup_callback()
        self.adapter = None

    def __enter__(self) -> "R2Inspector":
        """Context manager entry"""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> Literal[False]:
        """Context manager exit with cleanup"""
        self._cleanup()
        return False

    def __del__(self) -> None:
        """Destructor with cleanup"""
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
        **options: Any,
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
            if self._pipeline_builder is None:
                raise RuntimeError("Pipeline builder is not initialized")
            pipeline = self._pipeline_builder.build(options)

            # Determine parallel execution from configuration and backend safety
            use_parallel = bool(self.config.typed_config.pipeline.parallel_execution)
            if use_parallel and not getattr(self.adapter, "thread_safe", True):
                logger.info("Disabling parallel pipeline execution: backend is not thread-safe")
                use_parallel = False

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

    def close(self) -> None:
        """Close r2pipe connection."""
        self._cleanup()


__all__ = ["R2Inspector"]
