#!/usr/bin/env python3
"""Core inspector orchestrating analysis via pipeline and registry.

This module contains the R2Inspector class (the main analysis facade) plus
the lifecycle, setup and runtime helpers that were previously spread across
inspector_runtime.py, inspector_helpers.py, inspector_lifecycle.py and
inspector_setup.py.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any, Literal, Self, cast

from ..error_handling.classifier import ErrorCategory, ErrorSeverity, error_handler
from ..infrastructure.logging import get_logger
from ..infrastructure.memory import MemoryAwareAnalyzer
from ..interfaces import ConfigLike, FileValidatorLike, MemoryMonitorLike, ResultAggregatorLike
from .analyzer_factory import run_analysis_method
from .inspector_dispatch import InspectorDispatchMixin

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Dependency container (reduces constructor parameter count)
# ---------------------------------------------------------------------------


@dataclass
class InspectorDependencies:
    """Groups the injectable dependencies for R2Inspector construction.

    Instead of passing 8+ factory/callback kwargs individually, callers can
    build an ``InspectorDependencies`` instance and hand it over as a single
    argument.
    """

    adapter: Any
    registry_factory: Callable[[], Any]
    pipeline_builder_factory: Callable[[Any, Any, Any, str], Any]
    config_factory: Callable[[], Any] | None = None
    file_validator_factory: Callable[[str], Any] | None = None
    result_aggregator_factory: Callable[[], Any] | None = None
    memory_monitor: MemoryMonitorLike | None = None
    cleanup_callback: Callable[[], None] | None = None


# ---------------------------------------------------------------------------
# Module-level helpers (were in inspector_setup.py / inspector_runtime.py)
# ---------------------------------------------------------------------------


def _validate_config_source(config: Any | None, deps: InspectorDependencies) -> None:
    """Raise if neither a config object nor a config factory is provided."""
    if config is None and deps.config_factory is None:
        raise ValueError("config_factory must be provided when config is None")


def _assign_inspector_config(
    inspector: Any, config: Any | None, deps: InspectorDependencies
) -> None:
    """Set inspector.config from the supplied object or factory."""
    if config is not None:
        inspector.config = config
    elif deps.config_factory is not None:
        inspector.config = deps.config_factory()
    else:
        raise ValueError("Either config or config_factory must be provided")


def _setup_file_and_validator(
    inspector: Any,
    filename: str,
    deps: InspectorDependencies,
    _logger: Any,
) -> None:
    """Wire file path, validator and aggregator; run validation."""
    if deps.file_validator_factory is None or deps.result_aggregator_factory is None:
        raise ValueError("file_validator_factory and result_aggregator_factory must be provided")
    inspector.file_path = Path(filename)
    inspector._file_validator = deps.file_validator_factory(filename)
    inspector._result_aggregator = deps.result_aggregator_factory()

    _logger.debug("Starting file validation for: %s", filename)
    if not inspector._file_validator.validate():
        _logger.error("File validation failed for: %s", filename)
        raise ValueError(f"File validation failed: {filename}")
    _logger.debug("File validation passed")


def _initialize_inspector(
    inspector: Any,
    *,
    filename: str,
    config: Any | None,
    verbose: bool,
    deps: InspectorDependencies,
    _logger: Any,
) -> None:
    if deps.memory_monitor is None:
        raise ValueError("memory_monitor must be provided")
    if deps.adapter is None:
        raise ValueError("adapter must be provided")
    if deps.registry_factory is None or deps.pipeline_builder_factory is None:
        raise ValueError("registry_factory and pipeline_builder_factory must be provided")

    _validate_config_source(config, deps)

    inspector._cleanup_callback = deps.cleanup_callback
    inspector.adapter = deps.adapter
    inspector.registry = None
    inspector._pipeline_builder = None
    inspector.filename = filename
    inspector.verbose = verbose
    inspector._registry_factory = deps.registry_factory
    inspector._pipeline_builder_factory = deps.pipeline_builder_factory
    inspector._file_validator_factory = deps.file_validator_factory
    inspector._result_aggregator_factory = deps.result_aggregator_factory

    _assign_inspector_config(inspector, config, deps)
    _setup_file_and_validator(inspector, filename, deps, _logger)


def _init_infrastructure(inspector: Any, _logger: Any) -> None:
    """Initialize registry and pipeline builder for an inspector instance."""
    if inspector._registry_factory is None or inspector._pipeline_builder_factory is None:
        raise ValueError("registry_factory and pipeline_builder_factory must be provided")
    inspector.registry = inspector._registry_factory()
    inspector._pipeline_builder = inspector._pipeline_builder_factory(
        inspector.adapter, inspector.registry, inspector.config, inspector.filename
    )

    _logger.debug("R2Pipe adapter initialized")
    _logger.debug("Analyzer registry initialized with %s analyzers", len(inspector.registry))

    if inspector.verbose:
        for analyzer_info in inspector.registry.list_analyzers():
            _logger.debug(
                "Registered: %s (%s, formats: %s)",
                analyzer_info["name"],
                analyzer_info["category"],
                analyzer_info["file_formats"],
            )


def _cleanup(inspector: Any) -> None:
    """Clean up inspector resources and drop the active adapter reference."""
    if getattr(inspector, "_cleanup_callback", None) is not None:
        inspector._cleanup_callback()
    if hasattr(inspector, "adapter"):
        inspector.adapter = None


def _clear_adapter_cache(adapter: Any) -> None:
    """Flush any in-memory command cache on the adapter between analysis runs."""
    if not hasattr(adapter, "_cache"):
        return
    cache_lock = getattr(adapter, "_cache_lock", None)
    if cache_lock is not None:
        with cache_lock:
            adapter._cache.clear()
    else:
        adapter._cache.clear()


def _decide_parallel_execution(adapter: Any, config: Any, _logger: Any) -> bool:
    """Return True when parallel pipeline execution is both configured and safe."""
    use_parallel = bool(config.typed_config.pipeline.parallel_execution)
    if use_parallel and not getattr(adapter, "thread_safe", False):
        _logger.info("Disabling parallel pipeline execution: backend is not thread-safe")
        return False
    return use_parallel


def _collect_memory_stats(initial: dict[str, Any], final: dict[str, Any]) -> dict[str, Any]:
    """Build a memory-usage summary dict from two memory snapshots."""
    return {
        "initial_memory_mb": initial["process_memory_mb"],
        "final_memory_mb": final["process_memory_mb"],
        "memory_used_mb": final["process_memory_mb"] - initial["process_memory_mb"],
        "peak_memory_mb": final.get("peak_memory_mb", 0),
        "gc_count": final.get("gc_count", 0),
    }


def _analyze_impl(
    inspector: Any,
    _logger: Any,
    progress_callback: Callable[[str], None] | None,
    **options: Any,
) -> dict[str, Any]:
    """Execute an analysis run and normalize memory/error handling."""
    if getattr(inspector, "adapter", None) is None:
        raise RuntimeError("Inspector has been cleaned up — cannot analyze after close()")

    _clear_adapter_cache(inspector.adapter)

    initial_memory = inspector.memory_monitor.check_memory(force=True)
    _logger.debug(
        "Starting analysis with %.1fMB memory usage",
        initial_memory["process_memory_mb"],
    )

    try:
        if inspector._pipeline_builder is None:
            raise RuntimeError("Pipeline builder is not initialized")
        pipeline = inspector._pipeline_builder.build(options)

        use_parallel = _decide_parallel_execution(inspector.adapter, inspector.config, _logger)

        if progress_callback and not use_parallel:
            results = inspector._execute_with_progress(pipeline, options, progress_callback)
        else:
            results = inspector._execute_without_progress(pipeline, options, parallel=use_parallel)

        final_memory = inspector.memory_monitor.check_memory(force=True)
        results["memory_stats"] = _collect_memory_stats(initial_memory, final_memory)
        return cast(dict[str, Any], results)

    except MemoryError:
        _logger.error("Analysis failed due to memory constraints")
        inspector.memory_monitor._trigger_gc(aggressive=True)
        return {
            "error": "Memory limit exceeded",
            "memory_stats": inspector.memory_monitor.check_memory(force=True),
        }

    except Exception as exc:
        _logger.error("Analysis failed: %s", exc)
        return {
            "error": str(exc),
            "memory_stats": inspector.memory_monitor.check_memory(force=True),
        }


# ---------------------------------------------------------------------------
# Execution helpers (were in inspector_helpers.py)
# ---------------------------------------------------------------------------


class InspectorExecutionMixin(InspectorDispatchMixin):
    """Execution helpers plus convenience query methods for R2Inspector."""

    def _execute_with_progress(
        self,
        pipeline: Any,
        options: dict[str, Any],
        progress_callback: Callable[[str], None],
    ) -> dict[str, Any]:
        return self._as_dict(pipeline.execute_with_progress(progress_callback, options))

    def _execute_without_progress(
        self,
        pipeline: Any,
        options: dict[str, Any],
        parallel: bool = False,
    ) -> dict[str, Any]:
        return self._as_dict(pipeline.execute(options, parallel=parallel))


# ---------------------------------------------------------------------------
# Lifecycle mixin — single responsibility: resource management
# ---------------------------------------------------------------------------


class InspectorLifecycleMixin:
    """Context-manager protocol and resource cleanup for R2Inspector.

    Keeping lifecycle separate from construction and analysis ensures that
    each class has exactly one reason to change (SRP).
    """

    def _init_infrastructure(self) -> None:
        _init_infrastructure(self, logger)

    def _cleanup(self) -> None:
        _cleanup(self)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> Literal[False]:
        self._cleanup()
        return False

    def __del__(self) -> None:
        cleanup = getattr(self, "_cleanup", None)
        if callable(cleanup):
            cleanup()

    def close(self) -> None:
        self._cleanup()


# ---------------------------------------------------------------------------
# Main class — single responsibility: construction + analysis entry point
# ---------------------------------------------------------------------------


class R2Inspector(InspectorLifecycleMixin, InspectorExecutionMixin, MemoryAwareAnalyzer):
    """Main analysis facade using pipeline and registry."""

    def __init__(
        self,
        filename: str,
        config: ConfigLike | None = None,
        verbose: bool = False,
        *,
        deps: InspectorDependencies | None = None,
        # Legacy individual kwargs — kept for backward compatibility.
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
            deps: Pre-built dependency container (preferred).  When provided
                the individual factory kwargs are ignored.

        Raises:
            ValueError: If file validation fails
        """
        logger.debug("R2Inspector.__init__ called with filename: %s", filename)

        # Build deps from individual kwargs when not supplied directly.
        if deps is None:
            if memory_monitor is None:
                raise ValueError("memory_monitor must be provided")
            if adapter is None:
                raise ValueError("adapter must be provided")
            if registry_factory is None or pipeline_builder_factory is None:
                raise ValueError("registry_factory and pipeline_builder_factory must be provided")
            deps = InspectorDependencies(
                adapter=adapter,
                registry_factory=registry_factory,
                pipeline_builder_factory=pipeline_builder_factory,
                config_factory=config_factory,
                file_validator_factory=file_validator_factory,
                result_aggregator_factory=result_aggregator_factory,
                memory_monitor=memory_monitor,
                cleanup_callback=cleanup_callback,
            )

        effective_monitor = deps.memory_monitor
        if effective_monitor is None:
            raise ValueError("memory_monitor must be provided")
        super().__init__(effective_monitor)
        _initialize_inspector(
            self,
            filename=filename,
            config=config,
            verbose=verbose,
            deps=deps,
            _logger=logger,
        )

        logger.debug("Starting adapter and registry initialization")
        self._init_infrastructure()
        logger.debug("Infrastructure initialized successfully")

    # -- main analysis entry point -------------------------------------------

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
        return _analyze_impl(self, logger, progress_callback, **options)


__all__ = [
    "InspectorDependencies",
    "R2Inspector",
    "InspectorExecutionMixin",
    "InspectorLifecycleMixin",
    "run_analysis_method",
]
