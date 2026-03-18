#!/usr/bin/env python3
"""Factory helpers for constructing core analysis components."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .adapters.magic_provider import MagicDetectorProvider
from .adapters.r2pipe_adapter import R2PipeAdapter
from .config import Config
from .core.file_validator import FileValidator
from .core.inspector import InspectorDependencies, R2Inspector
from .core.pipeline_builder import PipelineBuilder
from .core.result_aggregator import ResultAggregator
from .infrastructure.r2_session import R2Session
from .interfaces import MemoryMonitorLike
from .pipeline_composition import default_pipeline_runtime_dependencies
from .registry.default_registry import create_default_registry
from .infrastructure.memory import get_global_memory_monitor
from .error_handling.classifier import initialize_error_handling

# Composition root: eagerly initialize cross-cutting concerns once.
initialize_error_handling()


def build_inspector_dependencies(
    r2: Any,
    config: Config,
    filename: str,
) -> tuple[Any, Any, Any]:
    """Build adapter, registry, and pipeline builder for R2Inspector."""
    adapter = R2PipeAdapter(r2)
    registry = create_default_registry()
    pipeline_builder = PipelineBuilder(
        adapter,
        registry,
        config,
        filename,
        magic_detector_provider=MagicDetectorProvider(),
        runtime_dependencies=default_pipeline_runtime_dependencies(),
    )
    return adapter, registry, pipeline_builder


def create_inspector(
    filename: str,
    config: Config | None = None,
    verbose: bool = False,
    memory_monitor: MemoryMonitorLike | None = None,
) -> R2Inspector:
    """Create an R2Inspector with default dependencies."""
    cfg = config or Config()
    monitor = memory_monitor or get_global_memory_monitor()
    validator = FileValidator(filename)
    if not validator.validate():
        raise ValueError(f"File validation failed: {filename}")
    file_size_mb = Path(filename).stat().st_size / (1024 * 1024)
    session = R2Session(filename)
    r2 = session.open(file_size_mb)
    try:
        adapter, _registry, _pipeline_builder = build_inspector_dependencies(
            r2,
            cfg,
            filename,
        )
        deps = InspectorDependencies(
            adapter=adapter,
            registry_factory=create_default_registry,
            pipeline_builder_factory=lambda adapter, registry, cfg, path: PipelineBuilder(
                adapter,
                registry,
                cfg,
                path,
                magic_detector_provider=MagicDetectorProvider(),
                runtime_dependencies=default_pipeline_runtime_dependencies(),
            ),
            config_factory=Config,
            file_validator_factory=lambda path: FileValidator(path),
            result_aggregator_factory=ResultAggregator,
            memory_monitor=monitor,
            cleanup_callback=session.close,
        )
        return R2Inspector(
            filename=filename,
            config=cfg,
            verbose=verbose,
            deps=deps,
        )
    except Exception:
        session.close()
        raise
