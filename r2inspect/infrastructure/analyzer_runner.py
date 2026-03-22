#!/usr/bin/env python3
"""Canonical helper for running analyzers by filepath."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from .logging import get_logger

_logger = get_logger(__name__)

AnalyzerT = TypeVar("AnalyzerT")

_adapter_context_factory: Callable[..., Any] | None = None


def configure_adapter_context(factory: Callable[..., Any]) -> None:
    """Set the adapter context manager factory (called once at startup)."""
    global _adapter_context_factory
    _adapter_context_factory = factory


__all__ = ["run_analyzer_on_file", "configure_adapter_context"]


def run_analyzer_on_file(
    analyzer_factory: Callable[..., AnalyzerT],
    filepath: str,
    *args: Any,
    **kwargs: Any,
) -> Any | None:
    """Run an analyzer using a temporary adapter opened for the given file."""
    if not Path(filepath).exists():
        return None
    if _adapter_context_factory is None:
        _logger.debug("Adapter context factory not configured")
        return None

    try:
        with _adapter_context_factory(filepath) as adapter:
            analyzer = analyzer_factory(adapter, filepath)
            analyze = getattr(analyzer, "analyze", None)
            if callable(analyze):
                return analyze(*args, **kwargs)
            return None
    except Exception as exc:
        _logger.debug("Analyzer run failed: %s", exc)
        return None
