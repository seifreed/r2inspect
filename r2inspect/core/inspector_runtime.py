#!/usr/bin/env python3
"""Setup, lifecycle and analysis-run helpers for R2Inspector.

Extracted from inspector.py so the facade module stays within the
structural size budget. Every function here is duck-typed on an
``inspector`` instance plus an explicit logger, so this module has no
import dependency on the R2Inspector class itself.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from .inspector import InspectorDependencies


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
