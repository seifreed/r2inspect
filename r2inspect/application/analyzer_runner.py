#!/usr/bin/env python3
"""Application helper for running analyzers by filepath."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from ..adapters.r2pipe_context import open_r2_adapter

AnalyzerT = TypeVar("AnalyzerT")


def run_analyzer_on_file(
    analyzer_factory: Callable[..., AnalyzerT],
    filepath: str,
    *args: Any,
    **kwargs: Any,
) -> Any | None:
    """
    Run an analyzer using a temporary adapter opened for the given file.

    This keeps adapter lifecycle management out of analyzer modules.
    """
    try:
        with open_r2_adapter(filepath) as adapter:
            analyzer = analyzer_factory(adapter, filepath)
            analyze = getattr(analyzer, "analyze", None)
            if callable(analyze):
                return analyze(*args, **kwargs)
            return None
    except Exception:
        return None
