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
from types import TracebackType
from typing import Any, Literal, Self

from ..error_handling.classifier import ErrorCategory, ErrorSeverity, error_handler
from ..infrastructure.logging import get_logger
from ..infrastructure.memory import MemoryAwareAnalyzer
from ..interfaces import (
    AnalyzerRegistryLike,
    BinaryAnalyzerInterface,
    ConfigLike,
    FileValidatorLike,
    MemoryMonitorLike,
    ResultAggregatorLike,
)
from .analyzer_factory import run_analysis_method
from .inspector_dispatch import InspectorDispatchMixin
from .inspector_runtime import (
    _analyze_impl,
    _cleanup,
    _init_infrastructure,
    _initialize_inspector,
)

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

    adapter: BinaryAnalyzerInterface
    registry_factory: Callable[[], AnalyzerRegistryLike]
    pipeline_builder_factory: Callable[[Any, Any, ConfigLike, str], Any]
    config_factory: Callable[[], ConfigLike] | None = None
    file_validator_factory: Callable[[str], FileValidatorLike] | None = None
    result_aggregator_factory: Callable[[], ResultAggregatorLike] | None = None
    memory_monitor: MemoryMonitorLike | None = None
    cleanup_callback: Callable[[], None] | None = None


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
        deps: InspectorDependencies,
    ):
        """Initialize R2Inspector with file, configuration and dependencies.

        Dependencies are supplied as a single ``InspectorDependencies``
        container, normally built by ``create_inspector``. Raises
        ValueError if a required dependency is missing or file validation
        fails.
        """
        logger.debug("R2Inspector.__init__ called with filename: %s", filename)

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
        """Run the full pipeline analysis.

        ``progress_callback`` receives stage names for progress display
        (used by the CLI). ``options`` are forwarded to the pipeline
        builder. Returns the results dict plus a ``memory_stats`` entry;
        on failure returns an ``error`` entry instead of raising.
        """
        return _analyze_impl(self, logger, progress_callback, **options)


__all__ = [
    "InspectorDependencies",
    "R2Inspector",
    "InspectorExecutionMixin",
    "InspectorLifecycleMixin",
    "run_analysis_method",
]
