#!/usr/bin/env python3
"""Canonical analyzer construction helpers."""

from __future__ import annotations

import inspect
import logging
from collections.abc import Iterable
from typing import Any

logger = logging.getLogger(__name__)

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


def _signature_accepts(sig: inspect.Signature, *args: Any, **kwargs: Any) -> bool:
    try:
        sig.bind(*args, **kwargs)
    except TypeError:
        return False
    return True


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
    sig: inspect.Signature | None
    try:
        sig = inspect.signature(analyzer_class)
    except (TypeError, ValueError):
        sig = None
    else:
        params = [param for param in sig.parameters if param != "self"]
        kwargs = _build_kwargs(params, backend, config, filename)
        if _signature_accepts(sig, **kwargs):
            return analyzer_class(**kwargs)

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
        if sig is not None and not _signature_accepts(sig, *args):
            continue
        try:
            return analyzer_class(*args)
        except TypeError:
            if sig is not None:
                raise
            continue
    return analyzer_class()


def run_analysis_method(analyzer: object, method_names: Iterable[str]) -> Any:
    """Run the first available analysis method from a list."""
    tried = tuple(method_names)
    for method_name in tried:
        method = getattr(analyzer, method_name, None)
        if callable(method):
            return method()
    # No analyze/detect/scan method means this analyzer silently contributes an
    # error result to the report; surface which analyzer so a misconfigured or
    # newly added one is diagnosable instead of vanishing.
    logger.warning(
        "%s exposes none of the analysis methods %s; returning an error result",
        type(analyzer).__name__,
        tried,
    )
    return {"error": "No suitable analysis method found"}
