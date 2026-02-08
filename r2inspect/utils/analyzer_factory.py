#!/usr/bin/env python3
"""Analyzer construction helpers."""

from __future__ import annotations

import inspect
from collections.abc import Iterable
from typing import Any

_R2_NAMES = {"r2", "r2pipe", "r2_instance"}
_ADAPTER_NAMES = {"adapter", "backend"}
_FILE_NAMES = {"filename", "file_path", "filepath"}


def _build_kwargs(params: Iterable[str], backend: Any, config: Any, filename: str | None) -> dict:
    kwargs: dict[str, Any] = {}
    for name in params:
        if name in _R2_NAMES or name in _ADAPTER_NAMES:
            kwargs[name] = backend
        elif name == "config":
            kwargs[name] = config
        elif name in _FILE_NAMES:
            kwargs[name] = filename
    return kwargs


def create_analyzer(
    analyzer_class: type,
    *,
    adapter: Any | None = None,
    r2: Any | None = None,
    config: Any | None = None,
    filename: str | None = None,
) -> Any:
    """Instantiate an analyzer using introspection and fallback signatures."""
    backend = adapter or r2
    try:
        sig = inspect.signature(analyzer_class)
        params = [p for p in sig.parameters if p != "self"]
        kwargs = _build_kwargs(params, backend, config, filename)
        try:
            return analyzer_class(**kwargs)
        except TypeError:
            pass
    except (TypeError, ValueError):
        pass

    candidates = [
        (backend, config, filename),
        (backend, config),
        (backend, filename),
        (filename, backend),
        (filename,),
        (backend,),
    ]
    for args in candidates:
        if any(arg is None for arg in args):
            continue
        try:
            return analyzer_class(*args)
        except TypeError:
            continue
    return analyzer_class()


def run_analysis_method(analyzer: Any, method_names: Iterable[str]) -> Any:
    """Run the first available method from a list on an analyzer."""
    for method_name in method_names:
        method = getattr(analyzer, method_name, None)
        if callable(method):
            return method()
    return {"error": "No suitable analysis method found"}
