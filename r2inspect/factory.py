#!/usr/bin/env python3
"""Factory helpers for constructing core analysis components."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .adapters.r2pipe_adapter import R2PipeAdapter
from .config import Config
from .core.file_validator import FileValidator
from .core.inspector import R2Inspector
from .core.pipeline_builder import PipelineBuilder
from .core.r2_session import R2Session
from .core.result_aggregator import ResultAggregator
from .registry.default_registry import create_default_registry
from .utils.memory_manager import global_memory_monitor


def build_inspector_dependencies(
    r2: Any,
    config: Config,
    filename: str,
) -> tuple[Any, Any, Any]:
    """Build adapter, registry, and pipeline builder for R2Inspector."""
    adapter = R2PipeAdapter(r2)
    registry = create_default_registry()
    pipeline_builder = PipelineBuilder(adapter, registry, config, filename)
    return adapter, registry, pipeline_builder


def create_inspector(
    filename: str,
    config: Config | None = None,
    verbose: bool = False,
) -> R2Inspector:
    """Create an R2Inspector with default dependencies."""
    cfg = config or Config()
    validator = FileValidator(filename)
    if not validator.validate():
        raise ValueError(f"File validation failed: {filename}")
    file_size_mb = Path(filename).stat().st_size / (1024 * 1024)
    session = R2Session(filename)
    r2 = session.open(file_size_mb)
    try:
        return R2Inspector(
            filename=filename,
            config=cfg,
            verbose=verbose,
            cleanup_callback=session.close,
            adapter=R2PipeAdapter(r2),
            registry_factory=create_default_registry,
            pipeline_builder_factory=lambda adapter, registry, cfg, path: PipelineBuilder(
                adapter, registry, cfg, path
            ),
            config_factory=Config,
            file_validator_factory=lambda _: validator,
            result_aggregator_factory=ResultAggregator,
            memory_monitor=global_memory_monitor,
        )
    except Exception:
        session.close()
        raise
