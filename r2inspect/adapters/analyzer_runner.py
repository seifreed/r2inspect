#!/usr/bin/env python3
"""Canonical helper for running analyzers by filepath."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from .r2pipe_context import open_r2_adapter

AnalyzerT = TypeVar("AnalyzerT")

__all__ = ["run_analyzer_on_file"]


def run_analyzer_on_file(
    analyzer_factory: Callable[..., AnalyzerT],
    filepath: str,
    *args: Any,
    **kwargs: Any,
) -> Any | None:
    """Run an analyzer using a temporary adapter opened for the given file."""
    if not Path(filepath).exists():
        return None

    try:
        with open_r2_adapter(filepath) as adapter:
            analyzer = analyzer_factory(adapter, filepath)
            analyze = getattr(analyzer, "analyze", None)
            if callable(analyze):
                return analyze(*args, **kwargs)
            return None
    except Exception:
        return None
